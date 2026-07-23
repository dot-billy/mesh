package nodeagent

import (
	"encoding/binary"
	"fmt"
)

const darwinTimevalSize = 16

// parseDarwinBootTime parses the little-endian 64-bit Darwin timeval returned
// for kern.boottime on the supported amd64 and arm64 targets. It is kept
// platform-neutral so malformed-kernel-output behavior is testable on Linux.
func parseDarwinBootTime(raw []byte) (string, bool) {
	if len(raw) == darwinTimevalSize-1 {
		// syscall.Sysctl treats a final binary NUL as a C-string terminator.
		raw = append(append([]byte(nil), raw...), 0)
	}
	if len(raw) != darwinTimevalSize {
		return "", false
	}
	seconds := int64(binary.LittleEndian.Uint64(raw[0:8]))
	microseconds := int32(binary.LittleEndian.Uint32(raw[8:12]))
	if seconds <= 0 || seconds >= 1<<40 || microseconds < 0 || microseconds >= 1_000_000 {
		return "", false
	}
	for _, value := range raw[12:16] {
		if value != 0 {
			return "", false
		}
	}
	bootID := fmt.Sprintf("darwin-boot-%d-%d", seconds, microseconds)
	return bootID, validIdentifier(bootID)
}
