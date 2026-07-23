package windowsinstall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const maxWindowsPersistedRootUpdates = 4096

var (
	windowsRootHistoryNamePattern = regexp.MustCompile(`^root-([0-9]{20})\.update\.json$`)
	windowsRootPendingNamePattern = regexp.MustCompile(`^\.root-([0-9]{20})\.update\.json\.new$`)
)

func windowsRootHistoryName(version uint64) string {
	return fmt.Sprintf("root-%020d.update.json", version)
}

func windowsRootPendingName(version uint64) string {
	return fmt.Sprintf(".root-%020d.update.json.new", version)
}

func windowsRootHistoryVersion(name string) (uint64, error) {
	match := windowsRootHistoryNamePattern.FindStringSubmatch(name)
	if len(match) != 2 {
		return 0, fmt.Errorf("invalid Windows root-history filename %q", name)
	}
	return parseWindowsRootVersion(match[1], name, windowsRootHistoryName)
}

func windowsRootPendingVersion(name string) (uint64, error) {
	match := windowsRootPendingNamePattern.FindStringSubmatch(name)
	if len(match) != 2 {
		return 0, fmt.Errorf("invalid Windows pending root-history filename %q", name)
	}
	return parseWindowsRootVersion(match[1], name, windowsRootPendingName)
}

func parseWindowsRootVersion(value, name string, canonical func(uint64) string) (uint64, error) {
	version, err := strconv.ParseUint(value, 10, 64)
	if err != nil || version == 0 || canonical(version) != name {
		return 0, fmt.Errorf("invalid Windows root-history version in %q", name)
	}
	return version, nil
}

func isWindowsRootHistoryNamespace(name string) bool {
	return strings.HasPrefix(name, "root-") || strings.HasPrefix(name, ".root-")
}
