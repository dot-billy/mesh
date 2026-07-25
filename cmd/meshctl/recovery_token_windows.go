//go:build windows

package main

import (
	"errors"
	"os"
)

// Windows ACL validation is outside Go's portable os.FileMode model. Refuse
// the file source instead of silently accepting a token that other principals
// may be able to read; environment and stdin remain available.
func validateRecoveryTokenFileSecurity(os.FileInfo) error {
	return errors.New("private recovery-token file permissions cannot be verified on Windows; use MESH_AGENT_RECOVERY_TOKEN or stdin")
}
