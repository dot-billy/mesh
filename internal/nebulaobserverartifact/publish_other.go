//go:build !linux

package nebulaobserverartifact

import (
	"errors"
	"os"
)

func renameNoReplace(_ *os.File, _, _ string) error {
	return errors.New("observer stage publication is only supported on Linux")
}
