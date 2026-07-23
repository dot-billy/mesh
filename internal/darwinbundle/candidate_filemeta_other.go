//go:build !linux && !darwin

package darwinbundle

import "os"

func singleLink(os.FileInfo) bool { return false }
