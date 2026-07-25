//go:build darwin

package main

import (
	"errors"

	"mesh/internal/darwininstall"
)

func validateInstalledRuntimeDirectory(binaryDirectory string) error {
	if err := darwininstall.ValidateProductionDarwinInstalledRuntime(binaryDirectory); err != nil {
		return err
	}
	return errors.New("Darwin production enrollment remains disabled until clean-host native lifecycle, signing, notarization, and installed-host evidence pass")
}
