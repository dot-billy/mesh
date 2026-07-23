//go:build !linux

package main

import (
	"errors"
	"io"
)

func assembleDarwinSnapshot([]string, io.Writer) error {
	return errors.New("assemble-darwin-snapshot requires Linux create-only directory publication semantics")
}
