//go:build !darwin && !windows

package main

import "errors"

func newSupervisedNebulaRuntime(runtimeOptions) (runtimeController, error) {
	return nil, errors.New("--supervise-nebula requires a Darwin package")
}
