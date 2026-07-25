//go:build linux && !amd64 && !arm64

package linuxinstall

import (
	"errors"
	"os"
)

func renameNoReplace(_ *os.File, _, _ string) error {
	return errors.New("atomic no-replace publication is unsupported on this Linux architecture")
}
