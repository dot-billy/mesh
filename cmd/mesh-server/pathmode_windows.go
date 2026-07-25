//go:build windows

package main

import (
	"os"

	"mesh/internal/windowssecurity"
)

// Windows ACLs are not represented by os.FileMode permission bits.
func secretPathPrivate(os.FileInfo) bool { return true }

func identityConfigFilePrivate(file *os.File, _ os.FileInfo) bool {
	return windowssecurity.InspectPrivateFileSingleLink(file, windowssecurity.RegularFile) == nil
}

func syncSecretDirectory(string) error { return nil }
