package darwincodesign

import (
	"errors"
	"path/filepath"
	"strings"
)

const (
	CodesignPath        = "/usr/bin/codesign"
	codesignIdentifier  = "com.apple.security.codesign"
	LaunchctlPath       = "/bin/launchctl"
	launchctlIdentifier = "com.apple.xpc.launchctl"
)

// VerificationArguments returns the sole accepted codesign argv for a target.
// The literal requirement begins with "=" so codesign compiles it as source
// rather than interpreting it as a requirement-file path.
func VerificationArguments(policy Policy, role, target string) ([]string, error) {
	if !cleanAbsolutePath(target) {
		return nil, errors.New("Darwin code-signing target must be a clean absolute non-root path")
	}
	requirement, err := policy.Requirement(role)
	if err != nil {
		return nil, err
	}
	return []string{"--verify", "--strict=all", "--test-requirement", "=" + requirement, target}, nil
}

func codesignSelfVerificationArguments() []string {
	requirement := `anchor apple and identifier "` + codesignIdentifier + `"`
	return []string{"--verify", "--strict=all", "--test-requirement", "=" + requirement, CodesignPath}
}

func launchctlVerificationArguments() []string {
	requirement := `anchor apple and identifier "` + launchctlIdentifier + `"`
	return []string{"--verify", "--strict=all", "--test-requirement", "=" + requirement, LaunchctlPath}
}

func cleanAbsolutePath(path string) bool {
	return path != "" && path != string(filepath.Separator) && filepath.IsAbs(path) &&
		filepath.Clean(path) == path && !strings.ContainsRune(path, '\x00')
}
