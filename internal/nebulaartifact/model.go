package nebulaartifact

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"sync"
	"unicode/utf8"

	nebulalock "mesh/third_party/nebula"
)

const (
	lockSchema          = "mesh.nebula-dependency-lock.v1"
	lockedRepository    = "https://github.com/slackhq/nebula"
	lockedTag           = "v1.10.3"
	lockedVersion       = "v1.10.3"
	lockedRevision      = "f573e8a26695278f9d71587390fbfe0d0933aa21"
	lockedInitialHost   = "github.com"
	lockedFinalHost     = "release-assets.githubusercontent.com"
	maxLockSize         = 256 << 10
	maxEntries          = 256
	maxArchiveSize      = 128 << 20
	maxExpandedSize     = 256 << 20
	maxEntrySize        = 64 << 20
	maxCompressionRatio = 200
)

// Target identifies one supported release target. It is never inferred from a
// downloaded filename.
type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Lock struct {
	Schema     string         `json:"schema"`
	Repository string         `json:"repository"`
	ReleaseID  int64          `json:"release_id"`
	ReleaseTag string         `json:"release_tag"`
	TagObject  string         `json:"tag_object"`
	Commit     string         `json:"commit"`
	Module     string         `json:"module"`
	Version    string         `json:"version"`
	Artifacts  []ArtifactLock `json:"artifacts"`
}

type ArtifactLock struct {
	Targets       []Target    `json:"targets"`
	AssetID       int64       `json:"asset_id"`
	Name          string      `json:"name"`
	URL           string      `json:"url"`
	Size          int64       `json:"size"`
	SHA256        string      `json:"sha256"`
	ArchiveFormat string      `json:"archive_format"`
	Entries       []EntryLock `json:"entries"`
}

type EntryLock struct {
	Name           string             `json:"name"`
	Type           string             `json:"type"`
	ArchiveMode    uint32             `json:"archive_mode"`
	OutputMode     uint32             `json:"output_mode"`
	Size           int64              `json:"size"`
	SHA256         string             `json:"sha256"`
	CompressedSize int64              `json:"compressed_size,omitempty"`
	CRC32          uint32             `json:"crc32,omitempty"`
	Compression    uint16             `json:"compression,omitempty"`
	Binary         *BinaryExpectation `json:"binary,omitempty"`
}

type BinaryExpectation struct {
	Format   string   `json:"format"`
	MainPath string   `json:"main_path"`
	Targets  []Target `json:"targets"`
}

var (
	embeddedOnce sync.Once
	embeddedLock Lock
	embeddedErr  error
)

// EmbeddedLock parses and validates the immutable lock embedded in the binary.
func EmbeddedLock() (Lock, error) {
	embeddedOnce.Do(func() {
		embeddedLock, embeddedErr = ParseLock(nebulalock.V1103Lock())
	})
	return cloneLock(embeddedLock), embeddedErr
}

// ParseLock is exported for independent lock review and tests. Runtime fetches
// always call EmbeddedLock and expose no alternate-lock input.
func ParseLock(raw []byte) (Lock, error) {
	var lock Lock
	if len(raw) == 0 || len(raw) > maxLockSize {
		return lock, fmt.Errorf("lock size must be between 1 and %d bytes", maxLockSize)
	}
	if err := decodeStrictJSON(raw, &lock); err != nil {
		return lock, fmt.Errorf("invalid Nebula lock: %w", err)
	}
	if lock.Schema != lockSchema || lock.Repository != lockedRepository || lock.ReleaseID != 283875123 || lock.ReleaseTag != lockedTag || lock.Version != lockedVersion || lock.Commit != lockedRevision {
		return lock, errors.New("lock release identity does not match the compiled Nebula trust policy")
	}
	if lock.TagObject != "afe3e8c52cd4b91e8c5f946bf2e624df6d311c13" || lock.Module != "github.com/slackhq/nebula" {
		return lock, errors.New("lock tag object or module identity is invalid")
	}
	if len(lock.Artifacts) == 0 || len(lock.Artifacts) > 8 {
		return lock, errors.New("lock must contain between one and eight artifacts")
	}
	selected := make(map[Target]struct{})
	assetIDs := make(map[int64]struct{})
	assetNames := make(map[string]struct{})
	for artifactIndex := range lock.Artifacts {
		artifact := &lock.Artifacts[artifactIndex]
		if err := validateArtifactLock(artifact); err != nil {
			return lock, fmt.Errorf("artifact %d: %w", artifactIndex, err)
		}
		if _, exists := assetIDs[artifact.AssetID]; exists {
			return lock, fmt.Errorf("artifact %d repeats asset ID", artifactIndex)
		}
		assetIDs[artifact.AssetID] = struct{}{}
		if _, exists := assetNames[artifact.Name]; exists {
			return lock, fmt.Errorf("artifact %d repeats asset name", artifactIndex)
		}
		assetNames[artifact.Name] = struct{}{}
		for _, target := range artifact.Targets {
			if _, exists := selected[target]; exists {
				return lock, fmt.Errorf("target %s/%s is selected more than once", target.OS, target.Arch)
			}
			selected[target] = struct{}{}
		}
	}
	for _, required := range []Target{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}} {
		if _, ok := selected[required]; !ok {
			return lock, fmt.Errorf("required target %s/%s is absent", required.OS, required.Arch)
		}
	}
	if len(selected) != 6 {
		return lock, errors.New("lock contains a target outside the six compiled targets")
	}
	return lock, nil
}

// Select returns the sole artifact pinned for a supported target.
func (lock Lock) Select(goos, goarch string) (ArtifactLock, error) {
	target := Target{OS: goos, Arch: goarch}
	for _, artifact := range lock.Artifacts {
		for _, candidate := range artifact.Targets {
			if candidate == target {
				return cloneArtifact(artifact), nil
			}
		}
	}
	return ArtifactLock{}, fmt.Errorf("unsupported Nebula target %q/%q", goos, goarch)
}

func validateArtifactLock(artifact *ArtifactLock) error {
	if len(artifact.Targets) == 0 || len(artifact.Targets) > 2 {
		return errors.New("invalid target count")
	}
	for _, target := range artifact.Targets {
		if !supportedTarget(target) {
			return fmt.Errorf("unsupported target %q/%q", target.OS, target.Arch)
		}
	}
	wantName := ""
	wantFormat := ""
	switch artifact.Targets[0].OS {
	case "linux":
		if len(artifact.Targets) != 1 {
			return errors.New("Linux artifact must select exactly one target")
		}
		wantName = "nebula-linux-" + artifact.Targets[0].Arch + ".tar.gz"
		wantFormat = "tar.gz"
	case "windows":
		if len(artifact.Targets) != 1 {
			return errors.New("Windows artifact must select exactly one target")
		}
		wantName = "nebula-windows-" + artifact.Targets[0].Arch + ".zip"
		wantFormat = "zip"
	case "darwin":
		if len(artifact.Targets) != 2 || !containsTarget(artifact.Targets, Target{OS: "darwin", Arch: "amd64"}) || !containsTarget(artifact.Targets, Target{OS: "darwin", Arch: "arm64"}) {
			return errors.New("Darwin artifact must select the exact universal target pair")
		}
		wantName = "nebula-darwin.zip"
		wantFormat = "zip"
	default:
		return errors.New("unsupported artifact operating system")
	}
	for _, target := range artifact.Targets {
		if target.OS != artifact.Targets[0].OS {
			return errors.New("artifact mixes operating systems")
		}
	}
	if artifact.AssetID <= 0 || artifact.Name == "" || strings.ContainsAny(artifact.Name, "/\\") {
		return errors.New("invalid asset identity")
	}
	if artifact.Name != wantName || artifact.ArchiveFormat != wantFormat {
		return errors.New("artifact name or archive format does not match its exact target")
	}
	parsedURL, err := url.Parse(artifact.URL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Hostname() != lockedInitialHost || !standardHTTPSPort(parsedURL) || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return errors.New("asset URL is not an exact safe GitHub HTTPS URL")
	}
	wantURL := "https://github.com/slackhq/nebula/releases/download/" + lockedTag + "/" + artifact.Name
	if artifact.URL != wantURL {
		return errors.New("asset URL does not match its locked tag and name")
	}
	if artifact.Size <= 0 || artifact.Size > maxArchiveSize || !isLowerHex(artifact.SHA256, 64) {
		return errors.New("invalid asset size or SHA-256")
	}
	if len(artifact.Entries) == 0 || len(artifact.Entries) > maxEntries {
		return errors.New("invalid archive entry count")
	}
	seen := make(map[string]struct{}, len(artifact.Entries))
	var expanded int64
	binaryRoles := make(map[string]int)
	for entryIndex := range artifact.Entries {
		entry := &artifact.Entries[entryIndex]
		if err := validateEntryLock(artifact, entry); err != nil {
			return fmt.Errorf("entry %d: %w", entryIndex, err)
		}
		if _, exists := seen[entry.Name]; exists {
			return fmt.Errorf("duplicate entry %q", entry.Name)
		}
		seen[entry.Name] = struct{}{}
		if entry.Type == "file" {
			expanded += entry.Size
			if expanded > maxExpandedSize {
				return errors.New("aggregate expanded size exceeds policy")
			}
		}
		if entry.Binary != nil {
			binaryRoles[entry.Binary.MainPath]++
		}
	}
	wantRuntime := "github.com/slackhq/nebula/cmd/nebula"
	if artifact.Targets[0].OS == "darwin" || artifact.Targets[0].OS == "windows" {
		wantRuntime = "github.com/slackhq/nebula/cmd/nebula-service"
	}
	if len(binaryRoles) != 2 || binaryRoles[wantRuntime] != 1 || binaryRoles["github.com/slackhq/nebula/cmd/nebula-cert"] != 1 {
		return errors.New("artifact must contain exactly its locked Nebula runtime and nebula-cert binaries")
	}
	if expanded > int64(maxCompressionRatio)*artifact.Size+(1<<20) {
		return errors.New("aggregate archive expansion ratio exceeds policy")
	}
	return nil
}

func validateEntryLock(artifact *ArtifactLock, entry *EntryLock) error {
	directory := entry.Type == "dir"
	if entry.Type != "file" && !directory {
		return errors.New("entry type must be file or dir")
	}
	if err := validateArchivePath(entry.Name, directory); err != nil {
		return err
	}
	if entry.ArchiveMode > 0o777 || entry.OutputMode > 0o777 {
		return errors.New("entry permissions exceed ordinary permission bits")
	}
	if directory {
		if entry.Size != 0 || entry.SHA256 != "" || entry.Binary != nil || entry.OutputMode == 0 {
			return errors.New("directory metadata is inconsistent")
		}
		return nil
	}
	if entry.Size < 0 || entry.Size > maxEntrySize || !isLowerHex(entry.SHA256, 64) || entry.OutputMode == 0 {
		return errors.New("invalid regular-file metadata")
	}
	if artifact.ArchiveFormat == "zip" {
		if entry.CompressedSize <= 0 && entry.Size != 0 {
			return errors.New("ZIP compressed size must be positive")
		}
		if entry.CompressedSize > artifact.Size || entry.Compression != 0 && entry.Compression != 8 {
			return errors.New("invalid ZIP compression metadata")
		}
		if entry.CompressedSize > 0 && entry.Size > int64(maxCompressionRatio)*entry.CompressedSize+1<<20 {
			return errors.New("ZIP compression ratio exceeds policy")
		}
	}
	if entry.Binary != nil {
		if err := validateBinaryExpectation(entry.Binary, artifact.Targets); err != nil {
			return err
		}
	}
	return nil
}

func validateBinaryExpectation(binary *BinaryExpectation, artifactTargets []Target) error {
	if binary.MainPath != "github.com/slackhq/nebula/cmd/nebula" && binary.MainPath != "github.com/slackhq/nebula/cmd/nebula-service" && binary.MainPath != "github.com/slackhq/nebula/cmd/nebula-cert" {
		return errors.New("unexpected Nebula executable package")
	}
	if binary.Format != "elf" && binary.Format != "pe" && binary.Format != "macho-fat" {
		return errors.New("unexpected executable format")
	}
	if len(binary.Targets) == 0 || len(binary.Targets) > 2 {
		return errors.New("invalid executable target count")
	}
	seen := make(map[Target]struct{})
	for _, target := range binary.Targets {
		if !supportedTarget(target) {
			return errors.New("unsupported executable target")
		}
		if _, exists := seen[target]; exists {
			return errors.New("duplicate executable target")
		}
		seen[target] = struct{}{}
	}
	if len(seen) != len(artifactTargets) {
		return errors.New("executable targets do not match artifact targets")
	}
	for _, target := range artifactTargets {
		if _, ok := seen[target]; !ok {
			return errors.New("executable target does not match artifact")
		}
	}
	if len(binary.Targets) == 2 && binary.Format != "macho-fat" {
		return errors.New("only a Mach-O universal binary may contain two targets")
	}
	switch binary.Format {
	case "elf":
		if len(binary.Targets) != 1 || binary.Targets[0].OS != "linux" {
			return errors.New("ELF expectation must be exactly one Linux target")
		}
	case "pe":
		if len(binary.Targets) != 1 || binary.Targets[0].OS != "windows" {
			return errors.New("PE expectation must be exactly one Windows target")
		}
	case "macho-fat":
		if len(binary.Targets) != 2 || !containsTarget(binary.Targets, Target{OS: "darwin", Arch: "amd64"}) || !containsTarget(binary.Targets, Target{OS: "darwin", Arch: "arm64"}) {
			return errors.New("Mach-O universal expectation must contain Darwin amd64 and arm64")
		}
	}
	return nil
}

func supportedTarget(target Target) bool {
	return (target.OS == "linux" || target.OS == "darwin" || target.OS == "windows") && (target.Arch == "amd64" || target.Arch == "arm64")
}

func validateArchivePath(name string, directory bool) error {
	if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return fmt.Errorf("unsafe archive path %q", name)
	}
	canonical := name
	if directory {
		if !strings.HasSuffix(name, "/") || strings.HasSuffix(name, "//") {
			return fmt.Errorf("directory path %q must have one trailing slash", name)
		}
		canonical = strings.TrimSuffix(name, "/")
	} else if strings.HasSuffix(name, "/") {
		return fmt.Errorf("file path %q has a trailing slash", name)
	}
	if canonical == "" || canonical == "." || path.Clean(canonical) != canonical || strings.Contains(canonical, ":") {
		return fmt.Errorf("non-canonical archive path %q", name)
	}
	for _, component := range strings.Split(canonical, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("unsafe archive path %q", name)
		}
	}
	return nil
}

func outputPath(entry EntryLock) string { return strings.TrimSuffix(entry.Name, "/") }

func isLowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func standardHTTPSPort(parsed *url.URL) bool { return parsed.Port() == "" || parsed.Port() == "443" }

func decodeStrictJSON(raw []byte, output any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	if err := validateJSONSurrogates(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	return nil
}

func validateJSONSurrogates(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(raw) {
				continue
			}
			index++
			if raw[index] != 'u' || index+4 >= len(raw) {
				continue
			}
			value, ok := parseHexQuad(raw[index+1 : index+5])
			if !ok {
				continue
			}
			index += 4
			switch {
			case value >= 0xd800 && value <= 0xdbff:
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return errors.New("unpaired high UTF-16 surrogate escape")
				}
				low, ok := parseHexQuad(raw[index+3 : index+7])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return errors.New("unpaired high UTF-16 surrogate escape")
				}
				index += 6
			case value >= 0xdc00 && value <= 0xdfff:
				return errors.New("unpaired low UTF-16 surrogate escape")
			}
		}
	}
	return nil
}

func parseHexQuad(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var value uint16
	for _, character := range raw {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func cloneLock(lock Lock) Lock {
	clone := lock
	clone.Artifacts = make([]ArtifactLock, len(lock.Artifacts))
	for index, artifact := range lock.Artifacts {
		clone.Artifacts[index] = cloneArtifact(artifact)
	}
	return clone
}

func cloneArtifact(artifact ArtifactLock) ArtifactLock {
	clone := artifact
	clone.Targets = append([]Target(nil), artifact.Targets...)
	clone.Entries = make([]EntryLock, len(artifact.Entries))
	for index, entry := range artifact.Entries {
		clone.Entries[index] = entry
		if entry.Binary != nil {
			binary := *entry.Binary
			binary.Targets = append([]Target(nil), entry.Binary.Targets...)
			clone.Entries[index].Binary = &binary
		}
	}
	return clone
}

func consumeJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
