//go:build linux && !amd64 && !arm64

package nebulaartifact

import (
	"errors"
	"os"
)

func renameNoReplace(_ *os.File, _ string, _, _ string) error {
	return errors.New("atomic no-replace directory publication is unsupported on this Linux architecture")
}
