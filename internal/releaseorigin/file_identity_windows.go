//go:build windows

package releaseorigin

import "os"

// Native Windows origin packaging remains outside the current Linux
// container proof. os.FileInfo does not expose a portable link count.
func singleLink(os.FileInfo) bool { return true }
