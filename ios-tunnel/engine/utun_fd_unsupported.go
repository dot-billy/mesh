//go:build !darwin && !ios

package iosmobile

import "errors"

func discoverUTUNFileDescriptor() (int, error) {
	return -1, errors.New("NetworkExtension utun transport is unavailable")
}
