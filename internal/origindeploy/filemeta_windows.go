//go:build windows

package origindeploy

import "os"

func singleLink(info os.FileInfo) bool { return info != nil }
