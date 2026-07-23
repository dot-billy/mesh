//go:build darwin

package darwininstall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"mesh/internal/darwinbundle"
	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

// CurrentSwitch owns one expected-prior-bound current-link transaction. Its
// temporary name is bound into the durable installer journal and can be
// reattached through ResumeCurrentSwitch after any crash boundary.
type CurrentSwitch struct {
	mu sync.Mutex

	layout        *ReleaseLayout
	expectedPrior string
	target        string
	temporaryName string
	inspection    darwinbundle.CandidateInspection
}

func (layout *ReleaseLayout) NewCurrentSwitch(expectedPrior string, target string, inspection darwinbundle.CandidateInspection) (*CurrentSwitch, error) {
	if err := validateDarwinCurrentSwitchIdentity(expectedPrior, target, inspection); err != nil {
		return nil, err
	}
	suffix, err := randomDarwinReleaseSuffix()
	if err != nil {
		return nil, err
	}
	return &CurrentSwitch{
		layout: layout, expectedPrior: expectedPrior, target: target,
		temporaryName: ".current-" + suffix, inspection: inspection,
	}, nil
}

func (layout *ReleaseLayout) ResumeCurrentSwitch(expectedPrior string, target string, temporaryName string, inspection darwinbundle.CandidateInspection) (*CurrentSwitch, error) {
	if err := validateDarwinCurrentSwitchIdentity(expectedPrior, target, inspection); err != nil {
		return nil, err
	}
	if !darwinCurrentTemporaryPattern.MatchString(temporaryName) {
		return nil, errors.New("Darwin current-switch temporary name is not canonical")
	}
	return &CurrentSwitch{
		layout: layout, expectedPrior: expectedPrior, target: target,
		temporaryName: temporaryName, inspection: inspection,
	}, nil
}

func validateDarwinCurrentSwitchIdentity(expectedPrior string, target string, inspection darwinbundle.CandidateInspection) error {
	if target == "" || !darwinInstalledIDPattern.MatchString(target) || expectedPrior == target ||
		(expectedPrior != "" && !darwinInstalledIDPattern.MatchString(expectedPrior)) ||
		inspection.Schema != darwinbundle.CandidateInspectionSchema {
		return errors.New("Darwin current-switch identity is not canonical")
	}
	return nil
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
		return errors.New("Darwin current switch is required")
	}
	current.layout.mu.Lock()
	defer current.layout.mu.Unlock()
	current.mu.Lock()
	defer current.mu.Unlock()
	if err := current.layout.validateAnchorsLocked(); err != nil {
		return err
	}
	return switchCurrentRelease(current, current.expectedPrior, current.target)
}

// ProveSelected reauthenticates the immutable target and exact current-link
// selection under the same locks used by Execute.
func (current *CurrentSwitch) ProveSelected() error {
	if current == nil || current.layout == nil {
		return errors.New("Darwin current switch is required")
	}
	current.layout.mu.Lock()
	defer current.layout.mu.Unlock()
	current.mu.Lock()
	defer current.mu.Unlock()
	if err := current.layout.validateAnchorsLocked(); err != nil {
		return err
	}
	return proveCurrentRelease(current, current.target)
}

func (current *CurrentSwitch) InspectTarget() error {
	return current.layout.validatePublishedReleaseLocked(current.target, current.inspection)
}

func (current *CurrentSwitch) InspectCurrent() (currentReleaseSelection, error) {
	return current.layout.readCurrentLocked()
}

func (current *CurrentSwitch) InspectTemporary() (bool, error) {
	return inspectDarwinManagedSymlink(current.layout.rootFD, current.temporaryName, "releases/"+current.target)
}

func (current *CurrentSwitch) CreateTemporary() error {
	target := "releases/" + current.target
	if err := unix.Symlinkat(target, current.layout.rootFD, current.temporaryName); err != nil {
		return fmt.Errorf("create Darwin current-switch temporary: %w", err)
	}
	present, err := inspectDarwinManagedSymlink(current.layout.rootFD, current.temporaryName, target)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("Darwin current-switch temporary is absent after creation")
	}
	return nil
}

func (current *CurrentSwitch) RemoveTemporary() error {
	present, err := current.InspectTemporary()
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	return unix.Unlinkat(current.layout.rootFD, current.temporaryName, 0)
}

func (current *CurrentSwitch) SyncRoot() error {
	return current.layout.root.Sync()
}

func (current *CurrentSwitch) ReplaceCurrent() error {
	if err := current.InspectTarget(); err != nil {
		return err
	}
	selection, err := current.InspectCurrent()
	if err != nil {
		return err
	}
	if currentSelectionID(selection) != current.expectedPrior {
		return errors.New("Darwin current release changed immediately before replacement")
	}
	temporary, err := current.InspectTemporary()
	if err != nil {
		return err
	}
	if !temporary {
		return errors.New("Darwin current-switch temporary disappeared before replacement")
	}
	return unix.Renameat(current.layout.rootFD, current.temporaryName, current.layout.rootFD, "current")
}

func (layout *ReleaseLayout) validatePublishedReleaseLocked(installedID string, inspection darwinbundle.CandidateInspection) (returnErr error) {
	if !darwinInstalledIDPattern.MatchString(installedID) || inspection.Schema != darwinbundle.CandidateInspectionSchema {
		return errors.New("Darwin published-release inspection identity is invalid")
	}
	path := filepath.Join(layout.releasesPath, installedID)
	fd, err := unix.Openat(layout.releasesFD, installedID, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin published-release descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	stage := &ReleaseStage{
		layout: layout, installedID: installedID,
		name: ".stage-" + installedID + "-00000000000000000000000000000000",
		path: path, directory: directory, fd: fd, identity: darwinObjectIdentity(stat),
		inspection: inspection, staged: true, published: true,
	}
	return stage.validateFinalizedTreeLocked(installedID)
}

// InspectPublishedAuthority reconstructs the exact candidate inspection from
// the immutable published package.json and state-retained artifact digest,
// then reauthenticates the complete release tree. Rollback never trusts a
// remembered path or a partial filesystem observation.
func (layout *ReleaseLayout) InspectPublishedAuthority(authority AuthenticatedDarwinRelease) (inspection darwinbundle.CandidateInspection, returnErr error) {
	if layout == nil {
		return inspection, errors.New("Darwin release layout is required")
	}
	if err := authority.Validate(); err != nil {
		return inspection, err
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return inspection, err
	}
	if err := validateDarwinPublishedDirectoryBasic(layout.releasesFD, layout.releasesPath, authority.InstalledID); err != nil {
		return inspection, err
	}
	path := filepath.Join(layout.releasesPath, authority.InstalledID)
	fd, err := unix.Openat(layout.releasesFD, authority.InstalledID, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return inspection, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return inspection, errors.New("adopt Darwin published-release descriptor for rollback inspection")
	}
	defer func() { returnErr = errors.Join(returnErr, directory.Close()) }()
	var opened, visible unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return inspection, err
	}
	if err := unix.Fstatat(layout.releasesFD, authority.InstalledID, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return inspection, err
	}
	if darwinObjectIdentity(opened) != darwinObjectIdentity(visible) {
		return inspection, errors.New("Darwin published release changed while reconstructing rollback inspection")
	}
	if err := validateDarwinReleaseDirectoryStat(opened, darwinPublishedReleaseMode); err != nil {
		return inspection, err
	}
	packageJSON, err := readDarwinReleaseFile(fd, path, "package.json", darwinReleaseFileExpectation{
		mode: 0o444, digest: authority.PackageJSONSHA256,
	})
	if err != nil {
		return inspection, err
	}
	inspection, err = darwinbundle.ReconstructCandidateInspection(authority.ArtifactSHA256, packageJSON)
	if err != nil {
		return inspection, err
	}
	if inspection.PackageJSONSHA256 != authority.PackageJSONSHA256 || inspection.Package.Version != authority.Version ||
		inspection.Package.SecurityFloor != authority.BundleSecurityFloor ||
		inspection.Package.AgentStateReadMin != authority.AgentStateReadMin || inspection.Package.AgentStateReadMax != authority.AgentStateReadMax ||
		inspection.Package.AgentStateWriteVersion != authority.AgentStateWriteVersion || inspection.Package.Target.Arch != authority.Arch {
		return darwinbundle.CandidateInspection{}, errors.New("Darwin published package metadata differs from persisted release authority")
	}
	if err := layout.validatePublishedReleaseLocked(authority.InstalledID, inspection); err != nil {
		return darwinbundle.CandidateInspection{}, err
	}
	return inspection, nil
}

func (layout *ReleaseLayout) readCurrentLocked() (currentReleaseSelection, error) {
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(layout.rootFD, "current", &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return currentReleaseSelection{}, nil
	} else if err != nil {
		return currentReleaseSelection{}, err
	}
	target, err := readDarwinLinkAt(layout.rootFD, "current")
	if err != nil {
		return currentReleaseSelection{}, err
	}
	installedID, err := parseDarwinCurrentTarget(target)
	if err != nil {
		return currentReleaseSelection{}, err
	}
	if err := validateDarwinManagedSymlinkStat(visibleBefore, target); err != nil {
		return currentReleaseSelection{}, err
	}
	var visibleAfter unix.Stat_t
	if err := unix.Fstatat(layout.rootFD, "current", &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return currentReleaseSelection{}, err
	}
	if snapshotDarwinInstallStat(visibleBefore) != snapshotDarwinInstallStat(visibleAfter) {
		return currentReleaseSelection{}, errors.New("Darwin current symlink changed while reading")
	}
	if err := validateDarwinPublishedDirectoryBasic(layout.releasesFD, layout.releasesPath, installedID); err != nil {
		return currentReleaseSelection{}, err
	}
	return currentReleaseSelection{InstalledID: installedID, Exists: true}, nil
}

func inspectDarwinManagedSymlink(parentFD int, name string, expectedTarget string) (bool, error) {
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	target, err := readDarwinLinkAt(parentFD, name)
	if err != nil {
		return false, err
	}
	if target != expectedTarget {
		return false, fmt.Errorf("Darwin managed symlink %q has an unexpected target", name)
	}
	if err := validateDarwinManagedSymlinkStat(visibleBefore, target); err != nil {
		return false, err
	}
	var visibleAfter unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, err
	}
	if snapshotDarwinInstallStat(visibleBefore) != snapshotDarwinInstallStat(visibleAfter) {
		return false, fmt.Errorf("Darwin managed symlink %q changed while reading", name)
	}
	return true, nil
}

func validateDarwinManagedSymlinkStat(stat unix.Stat_t, target string) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFLNK || stat.Mode&0o7777 != 0o777 || stat.Uid != 0 || stat.Gid != 0 ||
		stat.Nlink != 1 || stat.Flags != 0 || stat.Size != int64(len(target)) {
		return errors.New("Darwin managed symlink must be exact root:wheel, single-link, mode-0777, and flag-free")
	}
	return nil
}

func readDarwinLinkAt(parentFD int, name string) (string, error) {
	buffer := make([]byte, 512)
	read, err := unix.Readlinkat(parentFD, name, buffer)
	if err != nil {
		return "", err
	}
	if read <= 0 || read >= len(buffer) {
		return "", errors.New("Darwin managed symlink target is outside its bound")
	}
	return string(buffer[:read]), nil
}

func parseDarwinCurrentTarget(target string) (string, error) {
	const prefix = "releases/"
	installedID := strings.TrimPrefix(target, prefix)
	if installedID == target || target != prefix+installedID || !darwinInstalledIDPattern.MatchString(installedID) {
		return "", errors.New("Darwin current target is not canonical releases/<installed-id>")
	}
	return installedID, nil
}

func validateDarwinPublishedDirectoryBasic(releasesFD int, releasesPath string, installedID string) error {
	var visible unix.Stat_t
	if err := unix.Fstatat(releasesFD, installedID, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := validateDarwinReleaseDirectoryStat(visible, darwinPublishedReleaseMode); err != nil {
		return err
	}
	return nodeagent.InspectDarwinSensitivePath(filepath.Join(releasesPath, installedID))
}
