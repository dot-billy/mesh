package darwininstall

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"mesh/internal/agentstate"
)

const DarwinInstallStateSchema = "mesh-darwin-install-state-v1"

var (
	darwinDigestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	darwinChannelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
)

// AuthenticatedDarwinRelease is the comparable authority identity retained
// after outer release verification and exact bundle inspection. InstalledID
// binds its epoch, sequence, release manifest, and artifact digest.
type AuthenticatedDarwinRelease struct {
	ReleaseEpoch                 uint64 `json:"release_epoch"`
	Sequence                     uint64 `json:"sequence"`
	TrustedRootVersion           uint64 `json:"trusted_root_version"`
	TrustedRootSHA256            string `json:"trusted_root_sha256"`
	InstallerBootstrapRootSHA256 string `json:"installer_bootstrap_root_sha256"`
	ChannelManifestSHA256        string `json:"channel_manifest_sha256"`
	ReleaseManifestSHA256        string `json:"release_manifest_sha256"`
	ArtifactSHA256               string `json:"artifact_sha256"`
	PackageJSONSHA256            string `json:"package_json_sha256"`
	Version                      string `json:"version"`
	MinimumSecurityFloor         uint64 `json:"minimum_security_floor"`
	BundleSecurityFloor          uint64 `json:"bundle_security_floor"`
	AgentStateReadMin            uint64 `json:"agent_state_read_min"`
	AgentStateReadMax            uint64 `json:"agent_state_read_max"`
	AgentStateWriteVersion       uint64 `json:"agent_state_write_version"`
	Channel                      string `json:"channel"`
	Arch                         string `json:"arch"`
	VerifiedAt                   string `json:"verified_at"`
	InstalledID                  string `json:"installed_id"`
}

type DarwinInstallState struct {
	Schema               string                      `json:"schema"`
	BootstrapTrustSHA256 string                      `json:"bootstrap_trust_sha256"`
	Channel              string                      `json:"channel"`
	Arch                 string                      `json:"arch"`
	HighWater            AuthenticatedDarwinRelease  `json:"high_water"`
	Active               *AuthenticatedDarwinRelease `json:"active,omitempty"`
	Previous             *AuthenticatedDarwinRelease `json:"previous,omitempty"`
}

func DarwinInstalledID(identity AuthenticatedDarwinRelease) string {
	if identity.ReleaseEpoch == 0 || identity.Sequence == 0 ||
		!darwinDigestPattern.MatchString(identity.ReleaseManifestSHA256) ||
		!darwinDigestPattern.MatchString(identity.ArtifactSHA256) {
		return ""
	}
	return fmt.Sprintf("e%020d-s%020d-r%s-a%s", identity.ReleaseEpoch, identity.Sequence, identity.ReleaseManifestSHA256[:16], identity.ArtifactSHA256[:16])
}

func (identity AuthenticatedDarwinRelease) Validate() error {
	if identity.ReleaseEpoch == 0 || identity.Sequence == 0 || identity.TrustedRootVersion == 0 {
		return errors.New("Darwin release epoch, sequence, and trusted-root version must be positive")
	}
	for label, digest := range map[string]string{
		"trusted root":        identity.TrustedRootSHA256,
		"installer bootstrap": identity.InstallerBootstrapRootSHA256,
		"channel manifest":    identity.ChannelManifestSHA256,
		"release manifest":    identity.ReleaseManifestSHA256,
		"artifact":            identity.ArtifactSHA256,
		"package JSON":        identity.PackageJSONSHA256,
	} {
		if !darwinDigestPattern.MatchString(digest) {
			return fmt.Errorf("Darwin %s digest is not canonical", label)
		}
	}
	if identity.MinimumSecurityFloor == 0 || identity.BundleSecurityFloor < identity.MinimumSecurityFloor {
		return errors.New("Darwin release security floors are invalid")
	}
	if err := validateDarwinSemVer(identity.Version); err != nil {
		return errors.New("Darwin release version is not canonical SemVer")
	}
	if identity.AgentStateReadMin == 0 || identity.AgentStateReadMax == 0 || identity.AgentStateWriteVersion == 0 ||
		identity.AgentStateReadMin > identity.AgentStateWriteVersion || identity.AgentStateWriteVersion > identity.AgentStateReadMax {
		return errors.New("Darwin release agent-state compatibility is invalid")
	}
	if !darwinChannelPattern.MatchString(identity.Channel) {
		return errors.New("Darwin release channel is not canonical")
	}
	if identity.Arch != "amd64" && identity.Arch != "arm64" {
		return errors.New("Darwin release architecture is unsupported")
	}
	if _, err := parseDarwinCanonicalTime(identity.VerifiedAt); err != nil {
		return fmt.Errorf("Darwin release verified_at: %w", err)
	}
	if identity.InstalledID != DarwinInstalledID(identity) {
		return errors.New("Darwin installed release ID differs from its authenticated authority")
	}
	return nil
}

func parseDarwinCanonicalTime(value string) (time.Time, error) {
	if strings.TrimSpace(value) != value {
		return time.Time{}, errors.New("must not contain surrounding whitespace")
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("must be canonical UTC RFC3339 without fractional seconds")
	}
	return parsed.UTC(), nil
}

func validateDarwinSemVer(version string) error {
	if version == "" || len(version) > 128 || strings.Count(version, "+") > 1 {
		return errors.New("invalid SemVer length or build metadata")
	}
	mainAndBuild := strings.SplitN(version, "+", 2)
	if len(mainAndBuild) == 2 && !validDarwinSemVerIdentifiers(mainAndBuild[1], false) {
		return errors.New("invalid SemVer build metadata")
	}
	mainAndPre := strings.SplitN(mainAndBuild[0], "-", 2)
	core := strings.Split(mainAndPre[0], ".")
	if len(core) != 3 {
		return errors.New("SemVer must contain major.minor.patch")
	}
	for _, number := range core {
		if !validDarwinNumericIdentifier(number) {
			return errors.New("SemVer core is not canonical")
		}
	}
	if len(mainAndPre) == 2 && !validDarwinSemVerIdentifiers(mainAndPre[1], true) {
		return errors.New("invalid SemVer prerelease")
	}
	return nil
}

func validDarwinSemVerIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character != '-' && (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
				return false
			}
		}
		if rejectNumericLeadingZero && allDarwinDigits(part) && !validDarwinNumericIdentifier(part) {
			return false
		}
	}
	return true
}

func validDarwinNumericIdentifier(value string) bool {
	return value != "" && allDarwinDigits(value) && (len(value) == 1 || value[0] != '0')
}

func allDarwinDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func (state DarwinInstallState) Validate() error {
	if state.Schema != DarwinInstallStateSchema {
		return errors.New("Darwin install-state schema is invalid")
	}
	if !darwinDigestPattern.MatchString(state.BootstrapTrustSHA256) {
		return errors.New("Darwin installer bootstrap-trust digest is not canonical")
	}
	if !darwinChannelPattern.MatchString(state.Channel) {
		return errors.New("Darwin installer release channel is not canonical")
	}
	if state.Arch != "amd64" && state.Arch != "arm64" {
		return errors.New("Darwin installer architecture is unsupported")
	}
	if err := state.HighWater.Validate(); err != nil {
		return fmt.Errorf("Darwin high-water release: %w", err)
	}
	if state.HighWater.InstallerBootstrapRootSHA256 != state.BootstrapTrustSHA256 || state.HighWater.Channel != state.Channel || state.HighWater.Arch != state.Arch {
		return errors.New("Darwin high-water release differs from installer trust or architecture")
	}
	for label, identity := range map[string]*AuthenticatedDarwinRelease{
		"active": state.Active, "previous": state.Previous,
	} {
		if identity == nil {
			continue
		}
		if err := identity.Validate(); err != nil {
			return fmt.Errorf("Darwin %s release: %w", label, err)
		}
		if identity.InstallerBootstrapRootSHA256 != state.BootstrapTrustSHA256 || identity.Channel != state.Channel || identity.Arch != state.Arch {
			return fmt.Errorf("Darwin %s release differs from installer trust or architecture", label)
		}
		position := compareDarwinReleasePosition(*identity, state.HighWater)
		if position > 0 {
			return fmt.Errorf("Darwin %s release exceeds the accepted high-water position", label)
		}
		if position == 0 && *identity != state.HighWater {
			return fmt.Errorf("Darwin %s release equivocates at the accepted high-water position", label)
		}
	}
	if state.Active != nil && state.Previous != nil && state.Active.InstalledID == state.Previous.InstalledID {
		return errors.New("Darwin active and previous releases must be distinct")
	}
	return nil
}

// CheckCandidate applies the non-rollback authority rules after outer
// threshold verification and exact Darwin bundle inspection.
func (state DarwinInstallState) CheckCandidate(candidate AuthenticatedDarwinRelease) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	if candidate.InstallerBootstrapRootSHA256 != state.BootstrapTrustSHA256 || candidate.Channel != state.Channel || candidate.Arch != state.Arch {
		return errors.New("Darwin candidate differs from installer trust or architecture")
	}
	position := compareDarwinReleasePosition(candidate, state.HighWater)
	if position < 0 {
		return fmt.Errorf("Darwin candidate position (%d,%d) is below accepted position (%d,%d)", candidate.ReleaseEpoch, candidate.Sequence, state.HighWater.ReleaseEpoch, state.HighWater.Sequence)
	}
	if candidate.MinimumSecurityFloor < state.HighWater.MinimumSecurityFloor {
		return fmt.Errorf("Darwin candidate security floor %d is below accepted floor %d", candidate.MinimumSecurityFloor, state.HighWater.MinimumSecurityFloor)
	}
	if position == 0 && candidate != state.HighWater {
		return errors.New("same-position Darwin candidate differs from the accepted authenticated release")
	}
	if position > 0 && candidate.TrustedRootVersion < state.HighWater.TrustedRootVersion {
		return fmt.Errorf("Darwin candidate trusted-root version %d is below accepted version %d", candidate.TrustedRootVersion, state.HighWater.TrustedRootVersion)
	}
	return nil
}

func (state DarwinInstallState) AdvanceHighWater(candidate AuthenticatedDarwinRelease) (DarwinInstallState, error) {
	if err := state.CheckCandidate(candidate); err != nil {
		return DarwinInstallState{}, err
	}
	next := cloneDarwinInstallState(state)
	next.HighWater = candidate
	return next, next.Validate()
}

func (state DarwinInstallState) ActivateAccepted() (DarwinInstallState, error) {
	if err := state.Validate(); err != nil {
		return DarwinInstallState{}, err
	}
	target := state.HighWater
	if target.BundleSecurityFloor < state.HighWater.MinimumSecurityFloor {
		return DarwinInstallState{}, errors.New("Darwin activation target cannot process the persisted security floor")
	}
	if state.Active == nil {
		if target.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
			return DarwinInstallState{}, fmt.Errorf("first Darwin activation target writes agent-state schema %d, want %d", target.AgentStateWriteVersion, agentstate.CurrentWriteVersion)
		}
	} else if err := validateDarwinAgentStateRollbackPair(*state.Active, target); err != nil {
		return DarwinInstallState{}, err
	}
	next := cloneDarwinInstallState(state)
	if next.Active != nil && *next.Active == target {
		return next, nil
	}
	next.Previous = cloneAuthenticatedDarwinRelease(next.Active)
	next.Active = &target
	return next, next.Validate()
}

func (state DarwinInstallState) RollbackPrevious() (DarwinInstallState, error) {
	if err := state.Validate(); err != nil {
		return DarwinInstallState{}, err
	}
	if state.Active == nil || state.Previous == nil {
		return DarwinInstallState{}, errors.New("Darwin rollback requires active and previous releases")
	}
	if state.Previous.BundleSecurityFloor < state.HighWater.MinimumSecurityFloor {
		return DarwinInstallState{}, errors.New("Darwin rollback target cannot process the persisted security floor")
	}
	if err := validateDarwinAgentStateRollbackPair(*state.Active, *state.Previous); err != nil {
		return DarwinInstallState{}, err
	}
	next := cloneDarwinInstallState(state)
	next.Active, next.Previous = next.Previous, next.Active
	return next, next.Validate()
}

func validateDarwinAgentStateRollbackPair(source, target AuthenticatedDarwinRelease) error {
	if target.AgentStateReadMin > source.AgentStateWriteVersion || target.AgentStateReadMax < source.AgentStateWriteVersion {
		return fmt.Errorf("Darwin target cannot read source agent-state schema %d", source.AgentStateWriteVersion)
	}
	if source.AgentStateReadMin > target.AgentStateWriteVersion || source.AgentStateReadMax < target.AgentStateWriteVersion {
		return fmt.Errorf("Darwin source cannot read target agent-state schema %d for rollback", target.AgentStateWriteVersion)
	}
	return nil
}

func compareDarwinReleasePosition(left, right AuthenticatedDarwinRelease) int {
	if left.ReleaseEpoch < right.ReleaseEpoch {
		return -1
	}
	if left.ReleaseEpoch > right.ReleaseEpoch {
		return 1
	}
	if left.Sequence < right.Sequence {
		return -1
	}
	if left.Sequence > right.Sequence {
		return 1
	}
	return 0
}

func cloneDarwinInstallState(state DarwinInstallState) DarwinInstallState {
	copy := state
	copy.Active = cloneAuthenticatedDarwinRelease(state.Active)
	copy.Previous = cloneAuthenticatedDarwinRelease(state.Previous)
	return copy
}

func cloneAuthenticatedDarwinRelease(identity *AuthenticatedDarwinRelease) *AuthenticatedDarwinRelease {
	if identity == nil {
		return nil
	}
	copy := *identity
	return &copy
}
