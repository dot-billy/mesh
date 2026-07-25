//go:build linux

package main

import (
	"errors"
	"path/filepath"
)

const linuxProductionReleasesRoot = "/opt/mesh/releases"

func validateInstalledRuntimeDirectory(binaryDirectory string) error {
	binaryDirectory = filepath.Clean(binaryDirectory)
	if filepath.Base(binaryDirectory) != "bin" {
		return errors.New("authenticated Linux runtime executables are not in a release bin directory")
	}
	releaseDirectory := filepath.Dir(binaryDirectory)
	if filepath.Dir(releaseDirectory) != linuxProductionReleasesRoot ||
		!installedReleaseIDPattern.MatchString(filepath.Base(releaseDirectory)) {
		return errors.New("authenticated Linux runtime is outside the installer-managed release root")
	}
	return nil
}
