//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package linuxbundle

import "os"

func singleLink(os.FileInfo) bool { return false }
