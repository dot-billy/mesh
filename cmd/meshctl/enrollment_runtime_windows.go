//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func validateInstalledRuntimeDirectory(binaryDirectory string) error {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return fmt.Errorf("resolve Windows ProgramData for installed runtime: %w", err)
	}
	binaryDirectory = filepath.Clean(binaryDirectory)
	if !samePath(filepath.Base(binaryDirectory), "bin") {
		return errors.New("authenticated Windows runtime executables are not in a release bin directory")
	}
	releaseDirectory := filepath.Dir(binaryDirectory)
	releasesRoot := filepath.Join(programData, "Mesh", "releases")
	if !samePath(filepath.Dir(releaseDirectory), releasesRoot) ||
		!installedReleaseIDPattern.MatchString(filepath.Base(releaseDirectory)) {
		return errors.New("authenticated Windows runtime is outside the installer-managed release root")
	}
	return nil
}
