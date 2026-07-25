//go:build windows

package main

import "os"

// Native Windows origin packaging remains unsupported until its certificate
// and key DACLs can be proven.
func originTLSFileAllowed(os.FileInfo, bool) bool { return false }
