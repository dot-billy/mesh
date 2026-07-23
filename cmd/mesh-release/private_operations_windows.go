//go:build windows

package main

import (
	"errors"
	"os"
)

const windowsPrivateKeyError = "private-key operations are disabled on Windows: verified owner-only Windows ACL support is not implemented; use a secured POSIX signing host"

func requirePrivateKeyOperationsSupported() error {
	return errors.New(windowsPrivateKeyError)
}

func validatePrivateFileSecurity(os.FileInfo) error {
	return requirePrivateKeyOperationsSupported()
}

func syncOutputParent(string) error {
	return errors.New("durable parent-directory synchronization is unavailable on Windows")
}
