//go:build linux

package linuxinstall

import (
	"bytes"
	"crypto/rand"
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
	"time"

	releasetrust "mesh/internal/release"
)

const (
	productionRootStoreDirectory = "/var/lib/mesh-installer/trust"
	rootHistoryDirectoryName     = "roots"
	rootStoreLockName            = "trust.lock"
	maxPersistedRootUpdates      = 4096
)

var (
	rootHistoryNamePattern = regexp.MustCompile(`^[0-9]{20}\.root-update\.json$`)
	rootPendingNamePattern = regexp.MustCompile(`^\.pending-[0-9a-f]{32}$`)
)

type RootStore struct {
	path       string
	uid        uint32
	initial    releasetrust.ParsedRoot
	initialRaw []byte
	hooks      rootStoreHooks
}

type rootStoreHooks struct {
	write               func(*os.File, []byte) (int, error)
	beforeFileSync      func() error
	beforeReadback      func(string) error
	beforeRename        func() error
	beforeDirectorySync func() error
	afterHistoryRead    func(string)
}

type RootStoreLock struct {
	store     *RootStore
	root      *os.Root
	directory *os.File
	lockFile  *os.File
	roots     *os.Root
	rootsDir  *os.File
	current   releasetrust.ParsedRoot
}

func NewRootStore(path string, expectedUID uint32, initial releasetrust.ParsedRoot) (*RootStore, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve root store: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute != path {
		return nil, errors.New("root store path must be canonical and absolute")
	}
	initialRaw, err := releasetrust.EncodeRoot(initial.Document)
	if err != nil {
		return nil, fmt.Errorf("encode initial root: %w", err)
	}
	parsed, err := releasetrust.ParseRoot(initialRaw)
	if err != nil || parsed.SHA256 != initial.SHA256 {
		return nil, errors.New("initial root digest does not match its canonical document")
	}
	return &RootStore{path: absolute, uid: expectedUID, initial: parsed, initialRaw: initialRaw}, nil
}

func (store *RootStore) Acquire() (lock *RootStoreLock, returnErr error) {
	if store == nil || store.path == "" {
		return nil, errors.New("root store is not configured")
	}
	if err := ensureRootStoreDirectories(store.path, store.uid); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(store.path)
	if err != nil {
		return nil, fmt.Errorf("anchor root store: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = root.Close()
		}
	}()
	directory, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open root store directory: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = directory.Close()
		}
	}()
	lockFile, err := openRootStoreLockFile(root, store.uid)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			_ = lockFile.Close()
		}
	}()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("another root update holds the trust lock")
		}
		return nil, fmt.Errorf("lock root store: %w", err)
	}
	rootsPath := filepath.Join(store.path, rootHistoryDirectoryName)
	roots, err := os.OpenRoot(rootsPath)
	if err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		return nil, fmt.Errorf("anchor root history: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = roots.Close()
		}
	}()
	rootsDir, err := roots.Open(".")
	if err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		return nil, fmt.Errorf("open root history directory: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = rootsDir.Close()
		}
	}()
	lock = &RootStoreLock{store: store, root: root, directory: directory, lockFile: lockFile, roots: roots, rootsDir: rootsDir}
	if err := lock.reconcilePending(); err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		return nil, err
	}
	current, err := lock.replay()
	if err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		return nil, err
	}
	lock.current = current
	return lock, nil
}

func (lock *RootStoreLock) Current() releasetrust.ParsedRoot {
	if lock == nil || lock.store == nil {
		return releasetrust.ParsedRoot{}
	}
	return cloneParsedRootForStore(lock.current)
}

// HistoryEmpty reports whether no authenticated successor has been persisted.
// It replays the anchored directory again so state migration cannot rely on a
// stale in-memory view if an out-of-process mutation occurred while locked.
func (lock *RootStoreLock) HistoryEmpty() (bool, error) {
	if err := lock.validateHeld(); err != nil {
		return false, err
	}
	replayed, err := lock.replay()
	if err != nil {
		return false, err
	}
	if replayed.Document.Version != lock.current.Document.Version || replayed.SHA256 != lock.current.SHA256 {
		return false, errors.New("root history changed while the trust lock was held")
	}
	return replayed.Document.Version == lock.store.initial.Document.Version, nil
}

// RootVersion returns one exact historical authority after first revalidating
// the complete append-only history. It is used only to resume a transaction
// whose trust decision was already fsynced with that version and digest.
func (lock *RootStoreLock) RootVersion(version uint64) (releasetrust.ParsedRoot, error) {
	if err := lock.validateHeld(); err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	latest, err := lock.replay()
	if err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	if latest.Document.Version != lock.current.Document.Version || latest.SHA256 != lock.current.SHA256 {
		return releasetrust.ParsedRoot{}, errors.New("root history changed while the trust lock was held")
	}
	if version < lock.store.initial.Document.Version || version > latest.Document.Version {
		return releasetrust.ParsedRoot{}, fmt.Errorf("trusted root version %d is not in persisted history", version)
	}
	if version == lock.store.initial.Document.Version {
		return cloneParsedRootForStore(lock.store.initial), nil
	}

	current := cloneParsedRootForStore(lock.store.initial)
	for next := current.Document.Version + 1; next <= version; next++ {
		name := rootHistoryName(next)
		raw, err := lock.readHistoryFile(name)
		if err != nil {
			return releasetrust.ParsedRoot{}, err
		}
		update, err := releasetrust.ParseRootUpdate(raw)
		if err != nil {
			return releasetrust.ParsedRoot{}, fmt.Errorf("parse root history %s: %w", name, err)
		}
		transition, err := releasetrust.VerifyRootTransition(current, update.RootManifest, update.Signatures)
		if err != nil {
			return releasetrust.ParsedRoot{}, fmt.Errorf("verify root history %s: %w", name, err)
		}
		current = transition.Root
	}
	return cloneParsedRootForStore(current), nil
}

func (lock *RootStoreLock) ApplyChain(rawUpdates [][]byte, now time.Time, clockSkew time.Duration) (releasetrust.RootChainResult, error) {
	if err := lock.validateHeld(); err != nil {
		return releasetrust.RootChainResult{}, err
	}
	if len(rawUpdates) > releasetrust.MaxRootUpdatesPerInput {
		return releasetrust.RootChainResult{}, fmt.Errorf("root update count must not exceed %d", releasetrust.MaxRootUpdatesPerInput)
	}
	result := releasetrust.RootChainResult{Root: cloneParsedRootForStore(lock.current)}
	var previousInputVersion uint64
	for index, raw := range rawUpdates {
		update, err := releasetrust.ParseRootUpdate(raw)
		if err != nil {
			return result, fmt.Errorf("root update %d: %w", index, err)
		}
		candidate, err := releasetrust.ParseRoot(update.RootManifest)
		if err != nil {
			return result, fmt.Errorf("root update %d manifest: %w", index, err)
		}
		version := candidate.Document.Version
		if index != 0 && version <= previousInputVersion {
			return result, errors.New("root update versions must be strictly increasing")
		}
		previousInputVersion = version
		if version < lock.current.Document.Version {
			continue
		}
		if version == lock.current.Document.Version {
			if candidate.SHA256 != lock.current.SHA256 {
				return result, fmt.Errorf("root equivocation at version %d", version)
			}
			continue
		}
		transition, err := releasetrust.VerifyRootTransition(lock.current, update.RootManifest, update.Signatures)
		if err != nil {
			return result, fmt.Errorf("root update %d transition: %w", index, err)
		}
		if err := lock.publish(version, raw); err != nil {
			return result, fmt.Errorf("persist root version %d: %w", version, err)
		}
		lock.current = transition.Root
		result.Root = cloneParsedRootForStore(lock.current)
		result.Applied = append(result.Applied, releasetrust.AppliedRootUpdate{Raw: append([]byte(nil), raw...), Transition: transition})
	}
	if err := releasetrust.ValidateCurrentRoot(lock.current, now, clockSkew); err != nil {
		return result, err
	}
	return result, nil
}

func (lock *RootStoreLock) Close() error {
	if lock == nil {
		return nil
	}
	var unlockErr, lockCloseErr, rootsDirErr, rootsErr, directoryErr, rootErr error
	if lock.lockFile != nil {
		unlockErr = syscall.Flock(int(lock.lockFile.Fd()), syscall.LOCK_UN)
		lockCloseErr = lock.lockFile.Close()
	}
	if lock.rootsDir != nil {
		rootsDirErr = lock.rootsDir.Close()
	}
	if lock.roots != nil {
		rootsErr = lock.roots.Close()
	}
	if lock.directory != nil {
		directoryErr = lock.directory.Close()
	}
	if lock.root != nil {
		rootErr = lock.root.Close()
	}
	lock.store = nil
	lock.root = nil
	lock.directory = nil
	lock.lockFile = nil
	lock.roots = nil
	lock.rootsDir = nil
	lock.current = releasetrust.ParsedRoot{}
	return errors.Join(unlockErr, lockCloseErr, rootsDirErr, rootsErr, directoryErr, rootErr)
}

func ensureRootStoreDirectories(path string, expectedUID uint32) error {
	parent := filepath.Dir(path)
	if err := validateSecureAncestorChain(parent, false); err != nil {
		return fmt.Errorf("validate root store parent: %w", err)
	}
	created := false
	if err := os.Mkdir(path, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create root store: %w", err)
		}
	} else {
		created = true
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil || validateOnlinePrivateDirectoryInfo(info, expectedUID, false) != nil {
		return errors.New("root store must be an expected-owner mode-0700 real directory")
	}
	if created {
		if err := syncDirectory(parent); err != nil {
			return fmt.Errorf("sync root store parent: %w", err)
		}
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	rootsCreated := false
	if err := root.Mkdir(rootHistoryDirectoryName, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create root history: %w", err)
		}
	} else {
		rootsCreated = true
		if err := root.Chmod(rootHistoryDirectoryName, 0o700); err != nil {
			return err
		}
	}
	rootsInfo, err := root.Lstat(rootHistoryDirectoryName)
	if err != nil || validateOnlinePrivateDirectoryInfo(rootsInfo, expectedUID, false) != nil {
		return errors.New("root history must be an expected-owner mode-0700 real directory")
	}
	if rootsCreated {
		if err := syncRootDirectory(root); err != nil {
			return fmt.Errorf("sync root history creation: %w", err)
		}
	}
	return nil
}

func openRootStoreLockFile(root *os.Root, expectedUID uint32) (file *os.File, returnErr error) {
	before, err := root.Lstat(rootStoreLockName)
	created := false
	switch {
	case err == nil:
		if err := validateOnlinePrivateRegular(before, expectedUID, 0o600, 0, true); err != nil {
			return nil, fmt.Errorf("root store lock: %w", err)
		}
		file, err = root.OpenFile(rootStoreLockName, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	case errors.Is(err, os.ErrNotExist):
		file, err = root.OpenFile(rootStoreLockName, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		created = err == nil
		if errors.Is(err, os.ErrExist) {
			before, err = root.Lstat(rootStoreLockName)
			if err == nil {
				if validateErr := validateOnlinePrivateRegular(before, expectedUID, 0o600, 0, true); validateErr != nil {
					return nil, fmt.Errorf("root store lock: %w", validateErr)
				}
				file, err = root.OpenFile(rootStoreLockName, os.O_RDWR|syscall.O_NOFOLLOW, 0)
			}
		}
	default:
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			_ = file.Close()
		}
	}()
	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, err
		}
		if err := syncRootDirectory(root); err != nil {
			return nil, err
		}
		before, err = root.Lstat(rootStoreLockName)
		if err != nil {
			return nil, err
		}
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || validateOnlinePrivateRegular(opened, expectedUID, 0o600, 0, true) != nil {
		return nil, errors.New("root store lock changed while opening")
	}
	return file, nil
}

func (lock *RootStoreLock) replay() (releasetrust.ParsedRoot, error) {
	if _, err := lock.rootsDir.Seek(0, 0); err != nil {
		return releasetrust.ParsedRoot{}, fmt.Errorf("rewind root history: %w", err)
	}
	entries, err := lock.rootsDir.ReadDir(-1)
	if err != nil {
		return releasetrust.ParsedRoot{}, fmt.Errorf("list root history: %w", err)
	}
	if len(entries) > maxPersistedRootUpdates {
		return releasetrust.ParsedRoot{}, fmt.Errorf("root history count exceeds %d", maxPersistedRootUpdates)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !rootHistoryNamePattern.MatchString(name) {
			return releasetrust.ParsedRoot{}, fmt.Errorf("unknown root history entry %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	current := cloneParsedRootForStore(lock.store.initial)
	for _, name := range names {
		version, err := rootHistoryVersion(name)
		if err != nil {
			return releasetrust.ParsedRoot{}, err
		}
		if current.Document.Version == ^uint64(0) || version != current.Document.Version+1 {
			return releasetrust.ParsedRoot{}, fmt.Errorf("root history gap: version %d does not follow %d", version, current.Document.Version)
		}
		raw, err := lock.readHistoryFile(name)
		if err != nil {
			return releasetrust.ParsedRoot{}, err
		}
		update, err := releasetrust.ParseRootUpdate(raw)
		if err != nil {
			return releasetrust.ParsedRoot{}, fmt.Errorf("parse root history %s: %w", name, err)
		}
		candidate, err := releasetrust.ParseRoot(update.RootManifest)
		if err != nil || candidate.Document.Version != version {
			return releasetrust.ParsedRoot{}, fmt.Errorf("root history %s manifest version does not match filename", name)
		}
		transition, err := releasetrust.VerifyRootTransition(current, update.RootManifest, update.Signatures)
		if err != nil {
			return releasetrust.ParsedRoot{}, fmt.Errorf("verify root history %s: %w", name, err)
		}
		current = transition.Root
	}
	return current, nil
}

func (lock *RootStoreLock) reconcilePending() error {
	if _, err := lock.rootsDir.Seek(0, 0); err != nil {
		return fmt.Errorf("rewind root history: %w", err)
	}
	entries, err := lock.rootsDir.ReadDir(-1)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if !rootPendingNamePattern.MatchString(name) {
			continue
		}
		info, err := lock.roots.Lstat(name)
		if err != nil {
			return err
		}
		if validateOnlinePrivateRegular(info, lock.store.uid, 0o600, releasetrust.MaxRootUpdateSize, true) != nil &&
			validateOnlinePrivateRegular(info, lock.store.uid, 0o400, releasetrust.MaxRootUpdateSize, true) != nil {
			return fmt.Errorf("unsafe pending root history entry %q", name)
		}
		if err := lock.roots.Remove(name); err != nil {
			return fmt.Errorf("remove pending root history %q: %w", name, err)
		}
		removed = true
	}
	if removed {
		return syncRootDirectory(lock.roots)
	}
	return nil
}

func (lock *RootStoreLock) publish(version uint64, raw []byte) (returnErr error) {
	name := rootHistoryName(version)
	if _, err := lock.roots.Lstat(name); err == nil {
		existing, readErr := lock.readHistoryFile(name)
		if readErr != nil {
			return readErr
		}
		if bytes.Equal(existing, raw) {
			return nil
		}
		return fmt.Errorf("root history equivocation at version %d", version)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := randomRootPendingName()
	if err != nil {
		return err
	}
	file, err := lock.roots.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = lock.roots.Remove(temporary)
			_ = syncRootDirectory(lock.roots)
		}
	}()
	var written int
	if lock.store.hooks.write != nil {
		written, err = lock.store.hooks.write(file, raw)
	} else {
		written, err = file.Write(raw)
	}
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("write pending root history: %w", err)
	}
	if written != len(raw) {
		_ = file.Close()
		return errors.New("short root history write")
	}
	if lock.store.hooks.beforeFileSync != nil {
		if err := lock.store.hooks.beforeFileSync(); err != nil {
			_ = file.Close()
			return err
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(0o400); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if lock.store.hooks.beforeReadback != nil {
		if err := lock.store.hooks.beforeReadback(temporary); err != nil {
			return err
		}
	}
	readback, err := lock.readHistoryFile(temporary)
	if err != nil || !bytes.Equal(readback, raw) {
		return errors.New("pending root history readback differs from requested bytes")
	}
	if lock.store.hooks.beforeRename != nil {
		if err := lock.store.hooks.beforeRename(); err != nil {
			return err
		}
	}
	if err := renameNoReplace(lock.rootsDir, temporary, name); err != nil {
		return err
	}
	published = true
	if lock.store.hooks.beforeDirectorySync != nil {
		if err := lock.store.hooks.beforeDirectorySync(); err != nil {
			return err
		}
	}
	if err := syncRootDirectory(lock.roots); err != nil {
		return err
	}
	readback, err = lock.readHistoryFile(name)
	if err != nil || !bytes.Equal(readback, raw) {
		return errors.New("published root history readback differs from requested bytes")
	}
	return nil
}

func (lock *RootStoreLock) readHistoryFile(name string) ([]byte, error) {
	before, err := lock.roots.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := validateOnlinePrivateRegular(before, lock.store.uid, 0o400, releasetrust.MaxRootUpdateSize, false); err != nil {
		return nil, fmt.Errorf("root history %s: %w", name, err)
	}
	file, err := lock.roots.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, releasetrust.MaxRootUpdateSize+1))
	if lock.store.hooks.afterHistoryRead != nil {
		lock.store.hooks.afterHistoryRead(name)
	}
	after, statErr := file.Stat()
	closeErr := file.Close()
	current, pathErr := lock.roots.Lstat(name)
	if readErr != nil || statErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || validateOnlinePrivateRegular(after, lock.store.uid, 0o400, releasetrust.MaxRootUpdateSize, false) != nil {
		return nil, errors.New("root history file changed while reading")
	}
	if len(raw) > releasetrust.MaxRootUpdateSize {
		return nil, fmt.Errorf("root history exceeds %d bytes", releasetrust.MaxRootUpdateSize)
	}
	return raw, nil
}

func (lock *RootStoreLock) validateHeld() error {
	if lock == nil || lock.store == nil || lock.root == nil || lock.directory == nil || lock.lockFile == nil || lock.roots == nil || lock.rootsDir == nil {
		return errors.New("root store lock is not held")
	}
	pathInfo, pathErr := os.Lstat(lock.store.path)
	rootInfo, rootErr := lock.root.Stat(".")
	rootsInfo, rootsErr := lock.roots.Stat(".")
	if pathErr != nil || rootErr != nil || rootsErr != nil || !os.SameFile(pathInfo, rootInfo) ||
		validateOnlinePrivateDirectoryInfo(rootInfo, lock.store.uid, false) != nil || validateOnlinePrivateDirectoryInfo(rootsInfo, lock.store.uid, false) != nil {
		return errors.New("root store changed while lock was held")
	}
	return nil
}

func rootHistoryName(version uint64) string {
	return fmt.Sprintf("%020d.root-update.json", version)
}

func rootHistoryVersion(name string) (uint64, error) {
	if !rootHistoryNamePattern.MatchString(name) {
		return 0, fmt.Errorf("invalid root history filename %q", name)
	}
	value, err := strconv.ParseUint(strings.TrimSuffix(name, ".root-update.json"), 10, 64)
	if err != nil || value == 0 || rootHistoryName(value) != name {
		return 0, fmt.Errorf("invalid root history version in %q", name)
	}
	return value, nil
}

func randomRootPendingName() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return ".pending-" + hex.EncodeToString(random[:]), nil
}

func cloneParsedRootForStore(source releasetrust.ParsedRoot) releasetrust.ParsedRoot {
	raw, err := releasetrust.EncodeRoot(source.Document)
	if err != nil {
		return releasetrust.ParsedRoot{}
	}
	parsed, err := releasetrust.ParseRoot(raw)
	if err != nil || parsed.SHA256 != source.SHA256 {
		return releasetrust.ParsedRoot{}
	}
	return parsed
}
