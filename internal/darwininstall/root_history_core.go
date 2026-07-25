package darwininstall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const maxDarwinPersistedRootUpdates = 4096

var (
	darwinRootHistoryNamePattern = regexp.MustCompile(`^root-([0-9]{20})\.update\.json$`)
	darwinRootPendingNamePattern = regexp.MustCompile(`^\.root-([0-9]{20})\.update\.json\.new$`)
)

func darwinRootHistoryName(version uint64) string {
	return fmt.Sprintf("root-%020d.update.json", version)
}

func darwinRootPendingName(version uint64) string {
	return fmt.Sprintf(".root-%020d.update.json.new", version)
}

func darwinRootHistoryVersion(name string) (uint64, error) {
	match := darwinRootHistoryNamePattern.FindStringSubmatch(name)
	if len(match) != 2 {
		return 0, fmt.Errorf("invalid Darwin root-history filename %q", name)
	}
	return parseDarwinRootVersion(match[1], name, darwinRootHistoryName)
}

func darwinRootPendingVersion(name string) (uint64, error) {
	match := darwinRootPendingNamePattern.FindStringSubmatch(name)
	if len(match) != 2 {
		return 0, fmt.Errorf("invalid Darwin pending root-history filename %q", name)
	}
	return parseDarwinRootVersion(match[1], name, darwinRootPendingName)
}

func parseDarwinRootVersion(value, name string, canonical func(uint64) string) (uint64, error) {
	version, err := strconv.ParseUint(value, 10, 64)
	if err != nil || version == 0 || canonical(version) != name {
		return 0, fmt.Errorf("invalid Darwin root-history version in %q", name)
	}
	return version, nil
}

func isDarwinRootHistoryNamespace(name string) bool {
	return strings.HasPrefix(name, "root-") || strings.HasPrefix(name, ".root-")
}
