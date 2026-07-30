//go:build !linux && !windows && !darwin

package main

import (
	"fmt"
	"runtime"
)

func validateInstalledRuntimeDirectory(string) error {
	return fmt.Errorf("production enrollment has no supported runtime installer for %s", runtime.GOOS)
}
