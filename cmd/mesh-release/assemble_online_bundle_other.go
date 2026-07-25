//go:build !linux

package main

import (
	"errors"
	"io"
)

func assembleOnlineBundle([]string, io.Writer) error {
	return errors.New("assemble-online-bundle requires Linux stable-input and create-only publication semantics")
}
