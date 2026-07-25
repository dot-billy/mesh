//go:build linux

package nodeagent

import (
	"os"
	"strings"
)

func systemBootID() (string, bool) {
	value, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", false
	}
	bootID := strings.TrimSpace(string(value))
	return bootID, validIdentifier(bootID)
}
