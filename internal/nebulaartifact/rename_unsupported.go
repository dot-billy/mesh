//go:build !linux && !darwin && !windows

package nebulaartifact

import (
	"errors"
	"os"
)

func renameNoReplace(_ *os.File, _ string, _, _ string) error {
	return errors.New("atomic no-replace directory publication is unsupported on this operating system")
}
