//go:build windows

package main

import (
	"errors"
	"os"
)

func validateEnrollmentTokenFileSecurity(os.FileInfo) error {
	return errors.New("private enrollment-token file permissions cannot be verified on Windows; use --token-file -")
}
