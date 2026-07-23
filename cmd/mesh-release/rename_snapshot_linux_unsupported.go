//go:build linux && !amd64 && !arm64

package main

import "errors"

func renameSnapshotNoReplace(int, string, string) error {
	return errors.New("atomic create-only snapshot publication is unavailable on this Linux architecture")
}
