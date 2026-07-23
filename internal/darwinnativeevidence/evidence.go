// Package darwinnativeevidence validates one create-only native Mac proof
// directory without treating local evidence as remote attestation.
package darwinnativeevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	Schema               = "mesh-darwin-native-runtime-proof-v3"
	ProofLabel           = "io.mesh.node-agent.native-proof"
	MaximumReceiptSize   = 8 << 10
	maximumSystemSize    = 64 << 10
	maximumTestsSize     = 4 << 20
	maximumSourceSize    = 64 << 10
	maximumEvidenceAge   = 24 * time.Hour
	maximumFutureSkew    = 5 * time.Minute
	maximumProofDuration = 2 * time.Hour
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Receipt struct {
	Schema                  string
	Architecture            string
	SystemLaunchctlMutation bool
	SystemLaunchctlLabel    string
	BundleSHA256            string
	SystemSHA256            string
	TestsSHA256             string
	SourceSHA256            string
	StartedAt               string
	VerifiedAt              string
}

type Evidence struct {
	Receipt Receipt
	System  []byte
	Tests   []byte
	Source  []byte
}

func InspectDirectory(path string) (Evidence, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || absolute != filepath.Clean(path) || absolute == string(filepath.Separator) {
		return Evidence{}, errors.New("Darwin native evidence directory must be a clean absolute non-root path")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return Evidence{}, errors.New("Darwin native evidence directory cannot traverse symlinks")
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return Evidence{}, errors.Join(err, errors.New("Darwin native evidence root must be one real mode-0700 directory"))
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return Evidence{}, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return Evidence{}, err
	}
	wanted := map[string]int64{
		"receipt.txt": MaximumReceiptSize, "source.txt": maximumSourceSize,
		"system.txt": maximumSystemSize, "tests.txt": maximumTestsSize,
	}
	if len(entries) != len(wanted) {
		return Evidence{}, errors.New("Darwin native evidence directory has an unexpected entry count")
	}
	content := make(map[string][]byte, len(wanted))
	for _, entry := range entries {
		maximum, ok := wanted[entry.Name()]
		if !ok || entry.Type()&os.ModeSymlink != 0 {
			return Evidence{}, fmt.Errorf("Darwin native evidence contains unexpected entry %q", entry.Name())
		}
		file, err := root.Open(entry.Name())
		if err != nil {
			return Evidence{}, err
		}
		opened, statErr := file.Stat()
		raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
		after, afterErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || readErr != nil || afterErr != nil || closeErr != nil ||
			!opened.Mode().IsRegular() || opened.Mode().Perm() != 0o400 || opened.Size() < 1 || opened.Size() > maximum ||
			opened.Size() != int64(len(raw)) || !os.SameFile(opened, after) || opened.Mode() != after.Mode() || opened.Size() != after.Size() {
			return Evidence{}, errors.Join(statErr, readErr, afterErr, closeErr, fmt.Errorf("Darwin native evidence file %q changed or has invalid metadata", entry.Name()))
		}
		content[entry.Name()] = raw
	}
	receipt, err := ParseReceipt(content["receipt.txt"])
	if err != nil {
		return Evidence{}, err
	}
	for label, pair := range map[string]struct {
		raw  []byte
		want string
	}{
		"system": {content["system.txt"], receipt.SystemSHA256},
		"tests":  {content["tests.txt"], receipt.TestsSHA256},
		"source": {content["source.txt"], receipt.SourceSHA256},
	} {
		digest := sha256.Sum256(pair.raw)
		if hex.EncodeToString(digest[:]) != pair.want {
			return Evidence{}, fmt.Errorf("Darwin native %s evidence differs from its receipt", label)
		}
	}
	if err := validateSourceInventory(content["source.txt"]); err != nil {
		return Evidence{}, err
	}
	return Evidence{Receipt: receipt, System: content["system.txt"], Tests: content["tests.txt"], Source: content["source.txt"]}, nil
}

func ParseReceipt(raw []byte) (Receipt, error) {
	if len(raw) < 2 || len(raw) > MaximumReceiptSize || raw[len(raw)-1] != '\n' || bytes.Contains(raw, []byte{'\r'}) {
		return Receipt{}, errors.New("Darwin native receipt must be bounded LF-terminated UTF-8 text")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	keys := []string{
		"schema", "architecture", "system_launchctl_mutation_test", "system_launchctl_proof_label",
		"darwin_bundle_sha256", "system_sha256", "tests_sha256", "source_sha256", "started_at", "verified_at",
	}
	if len(lines) != len(keys) {
		return Receipt{}, errors.New("Darwin native receipt line count is invalid")
	}
	values := make(map[string]string, len(keys))
	for index, key := range keys {
		prefix := key + "="
		if !strings.HasPrefix(lines[index], prefix) || len(lines[index]) == len(prefix) {
			return Receipt{}, fmt.Errorf("Darwin native receipt line %d is not canonical %s", index+1, key)
		}
		values[key] = strings.TrimPrefix(lines[index], prefix)
	}
	receipt := Receipt{
		Schema: values["schema"], Architecture: values["architecture"],
		SystemLaunchctlMutation: values["system_launchctl_mutation_test"] == "1",
		SystemLaunchctlLabel:    values["system_launchctl_proof_label"], BundleSHA256: values["darwin_bundle_sha256"],
		SystemSHA256: values["system_sha256"], TestsSHA256: values["tests_sha256"], SourceSHA256: values["source_sha256"],
		StartedAt: values["started_at"], VerifiedAt: values["verified_at"],
	}
	if values["system_launchctl_mutation_test"] != "0" && values["system_launchctl_mutation_test"] != "1" {
		return Receipt{}, errors.New("Darwin native launchctl proof gate is invalid")
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func (evidence Evidence) MatchFull(now time.Time, arch, bundleSHA256 string) error {
	if err := validateReceipt(evidence.Receipt); err != nil {
		return err
	}
	if (arch != "amd64" && arch != "arm64") || !digestPattern.MatchString(bundleSHA256) {
		return errors.New("expected Darwin native evidence identity is invalid")
	}
	if evidence.Receipt.Architecture != arch || evidence.Receipt.BundleSHA256 != bundleSHA256 || !evidence.Receipt.SystemLaunchctlMutation {
		return errors.New("Darwin native evidence differs from the expected host or bundle, or omitted system launchctl mutation")
	}
	now = now.UTC()
	if now.IsZero() {
		return errors.New("Darwin native evidence comparison time is required")
	}
	verified, _ := time.Parse(time.RFC3339, evidence.Receipt.VerifiedAt)
	if verified.After(now.Add(maximumFutureSkew)) {
		return errors.New("Darwin native evidence time is in the future")
	}
	if now.Sub(verified) > maximumEvidenceAge {
		return errors.New("Darwin native evidence is older than 24 hours")
	}
	return nil
}

func validateReceipt(receipt Receipt) error {
	if receipt.Schema != Schema || (receipt.Architecture != "amd64" && receipt.Architecture != "arm64") ||
		receipt.SystemLaunchctlLabel != ProofLabel ||
		!digestPattern.MatchString(receipt.SystemSHA256) || !digestPattern.MatchString(receipt.TestsSHA256) || !digestPattern.MatchString(receipt.SourceSHA256) ||
		(receipt.BundleSHA256 != "none" && !digestPattern.MatchString(receipt.BundleSHA256)) || !canonicalTime(receipt.StartedAt) || !canonicalTime(receipt.VerifiedAt) {
		return errors.New("Darwin native receipt identity is invalid")
	}
	started, _ := time.Parse(time.RFC3339, receipt.StartedAt)
	verified, _ := time.Parse(time.RFC3339, receipt.VerifiedAt)
	if verified.Before(started) || verified.Sub(started) > maximumProofDuration {
		return errors.New("Darwin native receipt proof duration is invalid")
	}
	return nil
}

func validateSourceInventory(raw []byte) error {
	if len(raw) < 2 || raw[len(raw)-1] != '\n' || bytes.Contains(raw, []byte{'\r'}) {
		return errors.New("Darwin native source inventory is not canonical LF text")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	want := append([]string(nil), sourcePaths...)
	sort.Strings(want)
	if len(lines) != len(want) {
		return errors.New("Darwin native source inventory is incomplete")
	}
	for index, line := range lines {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || !digestPattern.MatchString(parts[0]) || parts[1] != want[index] {
			return fmt.Errorf("Darwin native source inventory line %d is invalid", index+1)
		}
	}
	return nil
}

func canonicalTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}

var sourcePaths = []string{
	"cmd/meshctl/agent_entry_other.go", "cmd/meshctl/agent_supervised_runtime_darwin.go",
	"cmd/meshctl/agent_supervised_runtime_darwin_test.go", "internal/darwinbundle/candidate.go",
	"internal/darwininstall/runtime_gate_darwin.go", "internal/darwininstall/runtime_gate_darwin_test.go",
	"internal/nodeagent/darwin_native_pathsecurity_test.go", "internal/nodeagent/pathsecurity_darwin.go",
	"internal/nodeagent/pathsecurity_platform_darwin.go", "packaging/launchd/io.mesh.node-agent.plist",
	"scripts/darwin-native-runtime-smoke.sh",
}
