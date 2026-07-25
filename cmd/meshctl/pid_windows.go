//go:build windows

package main

import (
	"errors"
)

func newPIDRuntime(_, _ string) (runtimeController, error) {
	return nil, errors.New("--reload-pid-file is not supported on Windows; use a managed service or --no-reload")
}
