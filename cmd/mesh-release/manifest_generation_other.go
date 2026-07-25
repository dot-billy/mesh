//go:build !linux

package main

import (
	"errors"
	"io"
)

func createReleaseManifest([]string, io.Writer) error {
	return errors.New("create-release-manifest requires a Linux host for secure local-artifact input semantics")
}

func createChannelManifest([]string, io.Writer) error {
	return errors.New("create-channel-manifest requires Linux secure manifest input semantics")
}
