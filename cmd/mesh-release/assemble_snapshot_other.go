//go:build !linux

package main

import (
	"errors"
	"io"
)

func assembleSnapshot([]string, io.Writer) error {
	return errors.New("assemble-snapshot requires Linux create-only directory publication semantics")
}
