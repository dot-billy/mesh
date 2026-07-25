//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package main

import (
	"errors"
	"os"
)

const unsupportedPrivateKeyError = "private-key operations require a supported secured POSIX signing host"

func requirePrivateKeyOperationsSupported() error {
	return errors.New(unsupportedPrivateKeyError)
}

func validatePrivateFileSecurity(os.FileInfo) error {
	return requirePrivateKeyOperationsSupported()
}

func syncOutputParent(string) error {
	return errors.New("durable parent-directory synchronization is unavailable on this platform")
}
