//go:build windows

package main

import (
	"fmt"
	"os"

	"mesh/internal/windowsauthenticode"
)

func authenticateWindowsInstallerSelf() (windowsauthenticode.Verification, error) {
	path, err := os.Executable()
	if err != nil {
		return windowsauthenticode.Verification{}, fmt.Errorf("resolve Windows installer executable: %w", err)
	}
	verification, err := windowsauthenticode.VerifyFile(path, windowsauthenticode.MeshSignerRole)
	if err != nil {
		return windowsauthenticode.Verification{}, fmt.Errorf("authenticate Windows installer publisher: %w", err)
	}
	return verification, nil
}
