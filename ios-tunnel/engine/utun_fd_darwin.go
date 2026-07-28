//go:build darwin || ios

package iosmobile

import (
	"errors"

	"golang.org/x/sys/unix"
)

const (
	utunControlName       = "com.apple.net.utun_control"
	maximumProviderFileFD = 1024
)

// discoverUTUNFileDescriptor follows Mobile Nebula's production iOS
// implementation: identify the AF_SYSTEM control socket that NetworkExtension
// created for this Packet Tunnel provider and give that descriptor directly to
// Nebula's FD-backed overlay device.
func discoverUTUNFileDescriptor() (int, error) {
	for fileDescriptor := 0; fileDescriptor <= maximumProviderFileFD; fileDescriptor++ {
		peer, err := unix.Getpeername(fileDescriptor)
		if err != nil {
			continue
		}
		control, ok := peer.(*unix.SockaddrCtl)
		if !ok {
			continue
		}
		info := &unix.CtlInfo{}
		copy(info.Name[:], utunControlName)
		if err := unix.IoctlCtlInfo(fileDescriptor, info); err != nil {
			continue
		}
		if control.ID == info.Id {
			return fileDescriptor, nil
		}
	}
	return -1, errors.New("NetworkExtension utun descriptor is unavailable")
}
