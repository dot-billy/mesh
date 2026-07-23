// Package buildinfo exposes the immutable identity compiled into Mesh
// executables. Release builds replace exactly one framed value with -ldflags
// -X; runtime reporting and offline bundle inspection both parse that same
// value so they cannot disagree about version, security-floor support, or
// agent-state read/write compatibility.
package buildinfo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"mesh/internal/agentstate"
)

const (
	Schema      = "mesh-build-identity-v1"
	FramePrefix = "MESH_BUILD_IDENTITY_V1."
	FrameSuffix = ".END_MESH_BUILD_IDENTITY_V1"

	DevelopmentIdentity = "mesh-development-build"

	maxIdentityJSONSize  = 4 << 10
	maxIdentityFrameSize = 8 << 10
)

var (
	commitPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	identifierRegex = regexp.MustCompile(`^[0-9A-Za-z-]+$`)
)

// Identity is the sole linker-set release identity. Production builds set it
// with:
//
//	-X mesh/internal/buildinfo.Identity=<canonical frame>
//
// The development sentinel is deliberately not a valid frame. Go's linker can
// retain an initialized string's original bytes after -X replacement; making
// the default unframed ensures a production ELF contains exactly one canonical
// identity for offline verification.
var Identity = DevelopmentIdentity

// IdentityInfo is the target-independent content of a compiled identity.
type IdentityInfo struct {
	Schema                 string `json:"schema"`
	Version                string `json:"version"`
	Commit                 string `json:"commit"`
	BuildTime              string `json:"build_time"`
	SecurityFloor          uint64 `json:"security_floor"`
	AgentStateReadMin      uint64 `json:"agent_state_read_min"`
	AgentStateReadMax      uint64 `json:"agent_state_read_max"`
	AgentStateWriteVersion uint64 `json:"agent_state_write_version"`
}

type Info struct {
	Version                string `json:"version"`
	Commit                 string `json:"commit"`
	BuildTime              string `json:"build_time"`
	GoVersion              string `json:"go_version"`
	OS                     string `json:"os"`
	Arch                   string `json:"arch"`
	SecurityFloor          uint64 `json:"security_floor"`
	AgentStateReadMin      uint64 `json:"agent_state_read_min"`
	AgentStateReadMax      uint64 `json:"agent_state_read_max"`
	AgentStateWriteVersion uint64 `json:"agent_state_write_version"`
}

// Current parses the same frame that an offline package verifier observes in
// the executable's read-only ELF image.
func Current() (Info, error) {
	if Identity == DevelopmentIdentity {
		return Info{
			Version: "dev", Commit: "unknown", BuildTime: "unknown", SecurityFloor: 1,
			AgentStateReadMin:      agentstate.CurrentSchemaVersion,
			AgentStateReadMax:      agentstate.CurrentSchemaVersion,
			AgentStateWriteVersion: agentstate.CurrentWriteVersion,
			GoVersion:              runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		}, nil
	}
	identity, err := ParseIdentity(Identity)
	if err != nil {
		return Info{}, fmt.Errorf("invalid compiled Mesh build identity: %w", err)
	}
	return Info{
		Version: identity.Version, Commit: identity.Commit,
		BuildTime: identity.BuildTime, SecurityFloor: identity.SecurityFloor,
		AgentStateReadMin: identity.AgentStateReadMin, AgentStateReadMax: identity.AgentStateReadMax,
		AgentStateWriteVersion: identity.AgentStateWriteVersion,
		GoVersion:              runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
	}, nil
}

// CurrentProduction rejects the development sentinel and framed development
// identities. Security-sensitive installer paths use this accessor so a build
// with forgotten release identity cannot authenticate or persist releases.
func CurrentProduction() (Info, error) {
	if Identity == DevelopmentIdentity {
		return Info{}, errors.New("development build identity cannot perform production operations")
	}
	info, err := Current()
	if err != nil {
		return Info{}, err
	}
	if info.Version == "dev" || info.Commit == "unknown" || info.BuildTime == "unknown" {
		return Info{}, errors.New("development build identity cannot perform production operations")
	}
	return info, nil
}

// EncodeIdentity returns the one canonical frame accepted by ParseIdentity.
// It is intended for release tooling, not as a runtime override.
func EncodeIdentity(identity IdentityInfo) (string, error) {
	if err := validateIdentity(identity); err != nil {
		return "", err
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("encode build identity: %w", err)
	}
	frame := FramePrefix + base64.RawURLEncoding.EncodeToString(raw) + FrameSuffix
	if len(frame) > maxIdentityFrameSize {
		return "", errors.New("encoded build identity exceeds its size bound")
	}
	return frame, nil
}

// ParseIdentity strictly decodes a canonical framed identity.
func ParseIdentity(frame string) (IdentityInfo, error) {
	var identity IdentityInfo
	if len(frame) == 0 || len(frame) > maxIdentityFrameSize ||
		!strings.HasPrefix(frame, FramePrefix) || !strings.HasSuffix(frame, FrameSuffix) {
		return identity, errors.New("build identity does not have the exact frame")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(frame, FramePrefix), FrameSuffix)
	if encoded == "" {
		return identity, errors.New("build identity payload is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxIdentityJSONSize || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return identity, errors.New("build identity payload is not canonical unpadded base64url")
	}
	if err := decodeStrictJSON(raw, &identity); err != nil {
		return IdentityInfo{}, fmt.Errorf("decode build identity: %w", err)
	}
	if err := validateIdentity(identity); err != nil {
		return IdentityInfo{}, err
	}
	canonical, err := json.Marshal(identity)
	if err != nil {
		return IdentityInfo{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return IdentityInfo{}, errors.New("build identity JSON is not canonical")
	}
	return identity, nil
}

func validateIdentity(identity IdentityInfo) error {
	if identity.Schema != Schema {
		return fmt.Errorf("unsupported build identity schema %q", identity.Schema)
	}
	if identity.SecurityFloor == 0 {
		return errors.New("build identity security floor must be positive")
	}
	if identity.AgentStateReadMin == 0 || identity.AgentStateReadMax == 0 || identity.AgentStateWriteVersion == 0 ||
		identity.AgentStateReadMin > identity.AgentStateWriteVersion || identity.AgentStateWriteVersion > identity.AgentStateReadMax {
		return errors.New("build identity agent-state read range and write version must be positive, ordered, and self-readable")
	}
	if identity.Version == "dev" {
		if identity.Commit != "unknown" || identity.BuildTime != "unknown" {
			return errors.New("development identity must use unknown commit and build time")
		}
		if identity.AgentStateReadMin != agentstate.CurrentSchemaVersion || identity.AgentStateReadMax != agentstate.CurrentSchemaVersion {
			return errors.New("development identity must read the current agent state schema")
		}
		if identity.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
			return errors.New("development identity must write the current agent state schema")
		}
		return nil
	}
	if err := validateSemVer(identity.Version); err != nil {
		return fmt.Errorf("build identity version: %w", err)
	}
	if !commitPattern.MatchString(identity.Commit) {
		return errors.New("build identity commit must be 40 lowercase hexadecimal characters")
	}
	parsed, err := time.Parse(time.RFC3339, identity.BuildTime)
	if err != nil || parsed.UTC().Format(time.RFC3339) != identity.BuildTime {
		return errors.New("build identity build time must be canonical UTC RFC3339 without fractional seconds")
	}
	return nil
}

func validateSemVer(version string) error {
	if version == "" || len(version) > 128 || strings.Count(version, "+") > 1 {
		return errors.New("invalid SemVer length or build metadata")
	}
	mainAndBuild := strings.SplitN(version, "+", 2)
	if len(mainAndBuild) == 2 && !validIdentifiers(mainAndBuild[1], false) {
		return errors.New("invalid SemVer build metadata")
	}
	mainAndPre := strings.SplitN(mainAndBuild[0], "-", 2)
	core := strings.Split(mainAndPre[0], ".")
	if len(core) != 3 {
		return errors.New("SemVer must contain major.minor.patch")
	}
	for _, number := range core {
		if !validNumericIdentifier(number) {
			return errors.New("SemVer core is not canonical")
		}
	}
	if len(mainAndPre) == 2 && !validIdentifiers(mainAndPre[1], true) {
		return errors.New("invalid SemVer prerelease")
	}
	return nil
}

func validIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, part := range strings.Split(value, ".") {
		if part == "" || !identifierRegex.MatchString(part) {
			return false
		}
		if rejectNumericLeadingZero && allDigits(part) && !validNumericIdentifier(part) {
			return false
		}
	}
	return true
}

func validNumericIdentifier(value string) bool {
	return value != "" && allDigits(value) && (len(value) == 1 || value[0] != '0')
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func decodeStrictJSON(raw []byte, output any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
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
			if _, duplicate := seen[key]; duplicate {
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
