//go:build !linux

package windowsbundle

import "os"

func singleLink(os.FileInfo) bool { return false }
