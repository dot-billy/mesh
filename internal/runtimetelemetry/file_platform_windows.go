//go:build windows

package runtimetelemetry

import (
	"errors"
	"os"
)

func lockTelemetryFile(*os.File) error {
	return errors.New("runtime telemetry file persistence requires a native Windows DACL and lock proof")
}

func unlockTelemetryFile(*os.File) error { return nil }

func ownedByCurrentUser(os.FileInfo) bool { return false }

func privateRegularFile(os.FileInfo) bool { return false }
