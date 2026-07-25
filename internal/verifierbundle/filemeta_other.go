//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package verifierbundle

import "os"

func singleLink(os.FileInfo) bool { return false }
