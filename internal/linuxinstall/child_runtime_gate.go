//go:build linux

package linuxinstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	productionChildRuntimeDirectory = "/run/mesh-agent"
	childRuntimeGateName            = "nebula.validated"
	childRuntimeGateRecoveryName    = ".nebula.validated.new"
	childRuntimeGateMode            = 0o400
)

var childRuntimeGateContent = []byte("mesh-nebula-validated-v1\n")

var errChildRuntimeGatePublicationPending = errors.New("agent runtime readiness marker has an unfinished publication")

type childRuntimeGateInspector interface {
	Inspect() (bool, error)
	ProveRuntimeDirectoryAbsent() error
}

// filesystemChildRuntimeGate is deliberately read-only. The lifecycle agent
// owns publication and removal; the installer independently proves that a
// running Nebula was authorized and that quiescence removed the authorization.
type filesystemChildRuntimeGate struct {
	directory   string
	expectedUID uint32
	expectedGID uint32
}

func productionChildRuntimeGate() *filesystemChildRuntimeGate {
	return &filesystemChildRuntimeGate{
		directory: productionChildRuntimeDirectory, expectedUID: 0, expectedGID: 0,
	}
}

func newFilesystemChildRuntimeGate(directory string, expectedUID, expectedGID uint32) (*filesystemChildRuntimeGate, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	if abs == string(filepath.Separator) || !filepath.IsAbs(abs) {
		return nil, errors.New("child runtime gate directory must be a non-root absolute path")
	}
	return &filesystemChildRuntimeGate{directory: abs, expectedUID: expectedUID, expectedGID: expectedGID}, nil
}

func (gate *filesystemChildRuntimeGate) Inspect() (open bool, returnErr error) {
	root, directory, absent, err := gate.openDirectory()
	if err != nil || absent {
		return false, err
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close(), root.Close()) }()

	live, err := gate.inspectFile(root, directory, childRuntimeGateName, false)
	if err != nil {
		return false, err
	}
	recovery, err := gate.inspectFile(root, directory, childRuntimeGateRecoveryName, true)
	if err != nil {
		return false, err
	}
	if recovery.found {
		validRecoveryOnly := !live.found && recovery.links == 1
		validLinkedPublication := live.found && live.complete && recovery.complete && live.links == 2 && recovery.links == 2 && live.identity == recovery.identity
		if !validRecoveryOnly && !validLinkedPublication {
			return false, errors.New("agent runtime readiness recovery state is not an exact interrupted publication")
		}
		return false, errChildRuntimeGatePublicationPending
	}
	if !live.found {
		return false, nil
	}
	if !live.complete || live.links != 1 {
		return false, errors.New("agent runtime readiness marker is not an exact single-link publication")
	}
	return true, nil
}

func (gate *filesystemChildRuntimeGate) ProveRuntimeDirectoryAbsent() error {
	if gate == nil || !filepath.IsAbs(gate.directory) || filepath.Clean(gate.directory) != gate.directory || gate.directory == string(filepath.Separator) {
		return errors.New("child runtime gate path is invalid")
	}
	if _, err := os.Lstat(gate.directory); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("agent RuntimeDirectory %q remains present", gate.directory)
}

type childRuntimeGateFile struct {
	found    bool
	complete bool
	links    uint64
	identity stateFileIdentity
}

func (gate *filesystemChildRuntimeGate) inspectFile(root *os.Root, directory *os.File, name string, allowPrefix bool) (childRuntimeGateFile, error) {
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return childRuntimeGateFile{}, nil
	}
	if err != nil {
		return childRuntimeGateFile{}, err
	}
	if err := gate.validateFileInfo(before, allowPrefix); err != nil {
		return childRuntimeGateFile{}, fmt.Errorf("agent runtime readiness file %q: %w", name, err)
	}
	path := filepath.Join(gate.directory, name)
	if err := rejectPOSIXACL(path); err != nil {
		return childRuntimeGateFile{}, err
	}
	descriptor, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return childRuntimeGateFile{}, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = syscall.Close(descriptor)
		return childRuntimeGateFile{}, errors.New("anchor agent runtime readiness file")
	}
	openedBefore, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(childRuntimeGateContent))+1))
	openedAfter, afterStatErr := file.Stat()
	visible, visibleErr := root.Lstat(name)
	closeErr := file.Close()
	if statErr != nil || readErr != nil || afterStatErr != nil || visibleErr != nil || closeErr != nil {
		return childRuntimeGateFile{}, errors.Join(statErr, readErr, afterStatErr, visibleErr, closeErr)
	}
	identities := make([]stateFileIdentity, 0, 4)
	for _, info := range []os.FileInfo{before, openedBefore, openedAfter, visible} {
		if err := gate.validateFileInfo(info, allowPrefix); err != nil {
			return childRuntimeGateFile{}, err
		}
		identity, err := stateIdentity(info)
		if err != nil {
			return childRuntimeGateFile{}, err
		}
		identities = append(identities, identity)
	}
	if identities[0] != identities[1] || identities[1] != identities[2] || identities[2] != identities[3] {
		return childRuntimeGateFile{}, fmt.Errorf("agent runtime readiness file %q changed while reading", name)
	}
	complete := bytes.Equal(content, childRuntimeGateContent)
	if !complete && (!allowPrefix || !bytes.HasPrefix(childRuntimeGateContent, content)) {
		return childRuntimeGateFile{}, fmt.Errorf("agent runtime readiness file %q has unexpected content", name)
	}
	if err := rejectPOSIXACL(path); err != nil {
		return childRuntimeGateFile{}, err
	}
	return childRuntimeGateFile{found: true, complete: complete, links: identities[0].links, identity: identities[0]}, nil
}

func (gate *filesystemChildRuntimeGate) openDirectory() (*os.Root, *os.File, bool, error) {
	if gate == nil || !filepath.IsAbs(gate.directory) || filepath.Clean(gate.directory) != gate.directory || gate.directory == string(filepath.Separator) {
		return nil, nil, false, errors.New("child runtime gate path is invalid")
	}
	visible, err := os.Lstat(gate.directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, true, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	if err := validateSecureAncestorChain(gate.directory, true); err != nil {
		return nil, nil, false, err
	}
	if err := gate.validateDirectoryInfo(visible); err != nil {
		return nil, nil, false, err
	}
	if err := rejectPOSIXACL(gate.directory); err != nil {
		return nil, nil, false, err
	}
	root, err := os.OpenRoot(gate.directory)
	if err != nil {
		return nil, nil, false, err
	}
	directory, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, nil, false, err
	}
	rootInfo, rootErr := root.Stat(".")
	directoryInfo, directoryErr := directory.Stat()
	pathInfo, pathErr := os.Lstat(gate.directory)
	if rootErr != nil || directoryErr != nil || pathErr != nil ||
		!os.SameFile(visible, rootInfo) || !os.SameFile(visible, directoryInfo) || !os.SameFile(visible, pathInfo) {
		_ = directory.Close()
		_ = root.Close()
		return nil, nil, false, errors.New("agent runtime readiness directory changed while anchoring")
	}
	return root, directory, false, nil
}

func (gate *filesystemChildRuntimeGate) validateDirectoryInfo(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Uid != gate.expectedUID || stat.Gid != gate.expectedGID {
		return errors.New("agent runtime readiness directory must have the exact expected owner and mode 0700")
	}
	return nil
}

func (gate *filesystemChildRuntimeGate) validateFileInfo(info os.FileInfo, allowPrefix bool) error {
	maximum := int64(len(childRuntimeGateContent))
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != childRuntimeGateMode ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 0 || info.Size() > maximum || !allowPrefix && info.Size() != maximum {
		return errors.New("must be an exact mode-0400 bounded regular readiness file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != gate.expectedUID || stat.Gid != gate.expectedGID || stat.Nlink < 1 || stat.Nlink > 2 {
		return errors.New("must have the exact expected owner and at most the publication link pair")
	}
	return nil
}
