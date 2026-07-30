package darwinnodepackage

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"

	"mesh/internal/darwininstall"
)

const (
	DirectoryKind = "directory"
	FileKind      = "file"

	PackageDirectoryMode = 0o700
	BootstrapFileMode    = 0o555
	SnapshotFileMode     = 0o400
	CompiledScriptMode   = 0o555
	CompiledPostinstall  = "postinstall"
	PackageOwnerUID      = 0
	PackageOwnerGID      = 0
)

// PayloadEntry is one package-root-relative entry. The install location is
// deliberately separate so no existing system ancestor can enter the BOM.
type PayloadEntry struct {
	Path string
	Kind string
	Mode uint32
	UID  uint32
	GID  uint32
}

type PayloadPlan struct {
	PackageIdentifier string
	Architecture      string
	InstallLocation   string
	Entries           []PayloadEntry
	Postinstall       PayloadEntry
}

// Plan returns the exact payload and script inventory for one architecture.
// It contains only one Mesh-owned package root, the authenticated bootstrap,
// and the three-file offline snapshot.
func Plan(policy Policy, architecture string) (PayloadPlan, error) {
	plan, err := planWithoutValidation(policy, architecture)
	if err != nil {
		return PayloadPlan{}, err
	}
	if err := plan.Validate(policy); err != nil {
		return PayloadPlan{}, err
	}
	return plan, nil
}

func (plan PayloadPlan) Validate(policy Policy) error {
	if err := validateUsablePolicy(policy); err != nil {
		return err
	}
	if plan.PackageIdentifier != policy.PackageIdentifier ||
		plan.InstallLocation != policy.PackageInstallLocation ||
		(plan.Architecture != "arm64" && plan.Architecture != "amd64") ||
		plan.Postinstall != rootWheelEntry(CompiledPostinstall, FileKind, CompiledScriptMode) {
		return errors.New("Darwin node package plan identity or compiled script is invalid")
	}
	expected, err := planWithoutValidation(policy, plan.Architecture)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(plan.Entries, expected.Entries) {
		return errors.New("Darwin node package payload differs from the exact six-entry plan")
	}
	for _, entry := range plan.Entries {
		if entry.Path == "" || path.IsAbs(entry.Path) || path.Clean(entry.Path) != entry.Path ||
			entry.Path == "." || strings.HasPrefix(entry.Path, "../") ||
			entry.UID != PackageOwnerUID || entry.GID != PackageOwnerGID {
			return fmt.Errorf("Darwin node package entry %q is not canonical root:wheel", entry.Path)
		}
	}
	return nil
}

// planWithoutValidation avoids recursive validation while
// still constructing the canonical comparison value.
func planWithoutValidation(policy Policy, architecture string) (PayloadPlan, error) {
	if architecture != "arm64" && architecture != "amd64" {
		return PayloadPlan{}, errors.New("Darwin node package architecture must be arm64 or amd64")
	}
	if err := validateUsablePolicy(policy); err != nil {
		return PayloadPlan{}, err
	}
	relative := func(absolute string) string {
		return strings.TrimPrefix(absolute, policy.PackageInstallLocation+"/")
	}
	root := relative(policy.PackageRootPath)
	snapshot := relative(policy.PackageSnapshotPath)
	entries := []PayloadEntry{
		rootWheelEntry(root, DirectoryKind, PackageDirectoryMode),
		rootWheelEntry(relative(policy.InstalledBootstrapPath), FileKind, BootstrapFileMode),
		rootWheelEntry(snapshot, DirectoryKind, PackageDirectoryMode),
		rootWheelEntry(path.Join(snapshot, darwininstall.DarwinInstallSnapshotFile), FileKind, SnapshotFileMode),
		rootWheelEntry(path.Join(snapshot, darwininstall.DarwinInstallSnapshotBundleFile), FileKind, SnapshotFileMode),
		rootWheelEntry(path.Join(snapshot, darwininstall.DarwinInstallSnapshotArtifact), FileKind, SnapshotFileMode),
	}
	return PayloadPlan{
		PackageIdentifier: policy.PackageIdentifier,
		Architecture:      architecture,
		InstallLocation:   policy.PackageInstallLocation,
		Entries:           entries,
		Postinstall:       rootWheelEntry(CompiledPostinstall, FileKind, CompiledScriptMode),
	}, nil
}

func validateUsablePolicy(policy Policy) error {
	if !canonicalIdentifier(policy.PackageIdentifier) ||
		policy.PackageInstallLocation != PackageInstallLocation ||
		!boundedPath(policy.PackageRootPath, policy.PackageInstallLocation) ||
		path.Dir(policy.PackageRootPath) != policy.PackageInstallLocation ||
		!boundedPath(policy.InstalledBootstrapPath, policy.PackageRootPath) ||
		path.Dir(policy.InstalledBootstrapPath) != policy.PackageRootPath ||
		path.Base(policy.InstalledBootstrapPath) != "mesh-install" ||
		!boundedPath(policy.PackageSnapshotPath, policy.PackageRootPath) ||
		path.Dir(policy.PackageSnapshotPath) != policy.PackageRootPath ||
		path.Base(policy.PackageSnapshotPath) != "snapshot" ||
		!canonicalSHA256(policy.SHA256) {
		return errors.New("Darwin node package policy is incomplete or unsafe")
	}
	return nil
}

func rootWheelEntry(name, kind string, mode uint32) PayloadEntry {
	return PayloadEntry{
		Path: name, Kind: kind, Mode: mode,
		UID: PackageOwnerUID, GID: PackageOwnerGID,
	}
}

func canonicalSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
