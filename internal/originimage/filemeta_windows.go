//go:build windows

package originimage

import "os"

func isSingleLink(info os.FileInfo) bool {
	return info != nil
}
