//go:build !linux && !windows

package nebulaartifact

import (
	"errors"
	"os"
)

func requireSecureIntakeHost(_ string, _ os.FileInfo) error {
	return errors.New("dependency intake is currently enabled only on Linux hosts; cross-stage any locked target from a private Linux directory")
}
