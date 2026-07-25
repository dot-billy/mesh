//go:build linux

// Package linuxinstall implements the Linux-only, release-rooted installation
// transaction. Installer state is deliberately separate from mesh-agent state
// so the confined lifecycle service cannot lower update trust floors.
package linuxinstall

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"mesh/internal/agentstate"
	"mesh/internal/installtrust"
	releasetrust "mesh/internal/release"
)

const (
	// LegacyStateSchema is retained only for the one-time, exact migration from
	// the pre-root installer. New root-aware state uses StateSchemaV3.
	LegacyStateSchema               = "mesh-linux-install-state-v2"
	StateSchemaV3                   = "mesh-linux-install-state-v3"
	LegacyStateSchemaVersion uint64 = 2
	StateSchemaVersion       uint64 = 3

	// StateSchema names the only schema written by the root-aware production
	// installer. LegacyStateSchema remains readable solely for exact migration.
	StateSchema = StateSchemaV3
)

var (
	lowerHex64Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	channelPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	identifierPattern  = regexp.MustCompile(`^[0-9A-Za-z-]+$`)
	installedIDPattern = regexp.MustCompile(`^` + installedIDPatternBody + `$`)
)

const installedIDPatternBody = `(?:s[0-9]{20}|e[0-9]{20}-s[0-9]{20})-r[0-9a-f]{16}-a[0-9a-f]{16}`

type TransactionPhase string

type TransactionOperation string

const (
	PhasePrepared        TransactionPhase = "prepared"
	PhaseServicesStopped TransactionPhase = "services_stopped"
	PhaseCurrentSwitched TransactionPhase = "current_switched"
	PhaseRollingBack     TransactionPhase = "rolling_back"

	OperationActivate TransactionOperation = "activate"
	OperationRollback TransactionOperation = "rollback"
)

// ReleaseIdentity binds an installed directory to the exact authenticated
// metadata, artifact, and inner bundle accepted for that sequence.
type ReleaseIdentity struct {
	ReleaseEpoch                 uint64 `json:"release_epoch,omitempty"`
	TrustedRootVersion           uint64 `json:"trusted_root_version,omitempty"`
	TrustedRootSHA256            string `json:"trusted_root_sha256,omitempty"`
	InstallerBootstrapRootSHA256 string `json:"installer_bootstrap_root_sha256,omitempty"`
	Sequence                     uint64 `json:"sequence"`
	ChannelManifestSHA256        string `json:"channel_manifest_sha256"`
	ReleaseManifestSHA256        string `json:"release_manifest_sha256"`
	ArtifactSHA256               string `json:"artifact_sha256"`
	BundleManifestSHA256         string `json:"bundle_manifest_sha256"`
	Version                      string `json:"version"`
	MinimumSecurityFloor         uint64 `json:"minimum_security_floor"`
	BundleSecurityFloor          uint64 `json:"bundle_security_floor"`
	AgentStateReadMin            uint64 `json:"agent_state_read_min"`
	AgentStateReadMax            uint64 `json:"agent_state_read_max"`
	AgentStateWriteVersion       uint64 `json:"agent_state_write_version"`
	VerifiedAt                   string `json:"verified_at"`
	InstalledID                  string `json:"installed_id"`
}

type PendingTransaction struct {
	Operation          TransactionOperation `json:"operation"`
	Candidate          ReleaseIdentity      `json:"candidate"`
	SourceActive       *ReleaseIdentity     `json:"source_active,omitempty"`
	SourcePrevious     *ReleaseIdentity     `json:"source_previous,omitempty"`
	TargetActive       ReleaseIdentity      `json:"target_active"`
	Phase              TransactionPhase     `json:"phase"`
	AgentWasEnabled    bool                 `json:"agent_was_enabled"`
	AgentWasActive     bool                 `json:"agent_was_active"`
	NebulaWasActive    bool                 `json:"nebula_was_active"`
	RuntimeGateWasOpen bool                 `json:"runtime_gate_was_open"`
	StartedAt          string               `json:"started_at"`
}

type State struct {
	Schema               string              `json:"schema"`
	TrustPolicySHA256    string              `json:"trust_policy_sha256,omitempty"`
	BootstrapTrustSHA256 string              `json:"bootstrap_trust_sha256,omitempty"`
	Channel              string              `json:"channel"`
	HighWater            ReleaseIdentity     `json:"high_water"`
	Active               *ReleaseIdentity    `json:"active,omitempty"`
	Previous             *ReleaseIdentity    `json:"previous,omitempty"`
	Pending              *PendingTransaction `json:"pending,omitempty"`
}

func InstalledID(identity ReleaseIdentity) string {
	if identity.Sequence == 0 || !lowerHex64Pattern.MatchString(identity.ReleaseManifestSHA256) || !lowerHex64Pattern.MatchString(identity.ArtifactSHA256) {
		return ""
	}
	if identity.ReleaseEpoch != 0 || identity.TrustedRootVersion != 0 || identity.TrustedRootSHA256 != "" {
		if identity.ReleaseEpoch == 0 || identity.TrustedRootVersion == 0 || !lowerHex64Pattern.MatchString(identity.TrustedRootSHA256) {
			return ""
		}
		return fmt.Sprintf("e%020d-s%020d-r%s-a%s", identity.ReleaseEpoch, identity.Sequence, identity.ReleaseManifestSHA256[:16], identity.ArtifactSHA256[:16])
	}
	return fmt.Sprintf("s%020d-r%s-a%s", identity.Sequence, identity.ReleaseManifestSHA256[:16], identity.ArtifactSHA256[:16])
}

func legacyInstalledID(identity ReleaseIdentity) string {
	if identity.Sequence == 0 || !lowerHex64Pattern.MatchString(identity.ReleaseManifestSHA256) || !lowerHex64Pattern.MatchString(identity.ArtifactSHA256) {
		return ""
	}
	return fmt.Sprintf("s%020d-r%s-a%s", identity.Sequence, identity.ReleaseManifestSHA256[:16], identity.ArtifactSHA256[:16])
}

func (identity ReleaseIdentity) Validate() error {
	return identity.validateForStateSchema("")
}

func (identity ReleaseIdentity) validateForStateSchema(schema string) error {
	hasAnyRootBinding := identity.ReleaseEpoch != 0 || identity.TrustedRootVersion != 0 || identity.TrustedRootSHA256 != "" || identity.InstallerBootstrapRootSHA256 != ""
	hasCompleteRootBinding := identity.ReleaseEpoch != 0 && identity.TrustedRootVersion != 0 && lowerHex64Pattern.MatchString(identity.TrustedRootSHA256) && lowerHex64Pattern.MatchString(identity.InstallerBootstrapRootSHA256)
	if hasAnyRootBinding && !hasCompleteRootBinding {
		return errors.New("release trusted-root binding is incomplete or noncanonical")
	}
	switch schema {
	case LegacyStateSchema:
		if hasAnyRootBinding {
			return errors.New("legacy release identity cannot carry a trusted-root binding")
		}
	case StateSchemaV3:
		if !hasCompleteRootBinding {
			return errors.New("v3 release identity requires an epoch and trusted-root binding")
		}
	case "":
	default:
		return fmt.Errorf("unsupported installer state schema %q", schema)
	}
	if identity.Sequence == 0 {
		return errors.New("release sequence must be positive")
	}
	for label, digest := range map[string]string{
		"channel manifest": identity.ChannelManifestSHA256,
		"release manifest": identity.ReleaseManifestSHA256,
		"artifact":         identity.ArtifactSHA256,
		"bundle manifest":  identity.BundleManifestSHA256,
	} {
		if !lowerHex64Pattern.MatchString(digest) {
			return fmt.Errorf("%s digest is not canonical", label)
		}
	}
	if err := validateSemVer(identity.Version); err != nil {
		return errors.New("release version is not canonical SemVer")
	}
	if identity.MinimumSecurityFloor == 0 || identity.BundleSecurityFloor == 0 || identity.MinimumSecurityFloor > identity.BundleSecurityFloor {
		return errors.New("release security floors are invalid")
	}
	if identity.AgentStateReadMin == 0 || identity.AgentStateReadMax == 0 || identity.AgentStateWriteVersion == 0 ||
		identity.AgentStateReadMin > identity.AgentStateWriteVersion || identity.AgentStateWriteVersion > identity.AgentStateReadMax {
		return errors.New("release agent-state read range and write version are invalid")
	}
	if _, err := parseCanonicalTime(identity.VerifiedAt); err != nil {
		return fmt.Errorf("release verified_at: %w", err)
	}
	expectedInstalledID := InstalledID(identity)
	preservedLegacyID := hasCompleteRootBinding && identity.ReleaseEpoch == 1 && identity.TrustedRootVersion == 1 && identity.InstalledID == legacyInstalledID(identity)
	if identity.InstalledID != expectedInstalledID && !preservedLegacyID {
		return errors.New("installed release ID does not match authenticated identity")
	}
	return nil
}

func (state State) Validate() error {
	switch state.Schema {
	case LegacyStateSchema:
		if !lowerHex64Pattern.MatchString(state.TrustPolicySHA256) {
			return errors.New("installer trust-policy digest is not canonical")
		}
		if state.BootstrapTrustSHA256 != "" {
			return errors.New("legacy installer state cannot carry a bootstrap-trust digest")
		}
	case StateSchemaV3:
		if state.TrustPolicySHA256 != "" {
			return errors.New("v3 installer state cannot carry a legacy trust-policy digest")
		}
		if !lowerHex64Pattern.MatchString(state.BootstrapTrustSHA256) {
			return errors.New("installer bootstrap-trust digest is not canonical")
		}
	default:
		return fmt.Errorf("unsupported installer state schema %q", state.Schema)
	}
	if !channelPattern.MatchString(state.Channel) {
		return errors.New("installer release channel is not canonical")
	}
	if err := state.HighWater.validateForStateSchema(state.Schema); err != nil {
		return fmt.Errorf("high-water release: %w", err)
	}
	for label, identity := range map[string]*ReleaseIdentity{"active": state.Active, "previous": state.Previous} {
		if identity == nil {
			continue
		}
		if err := identity.validateForStateSchema(state.Schema); err != nil {
			return fmt.Errorf("%s release: %w", label, err)
		}
		if state.Schema == StateSchemaV3 && identity.InstallerBootstrapRootSHA256 != state.HighWater.InstallerBootstrapRootSHA256 {
			return fmt.Errorf("%s release differs from the accepted installer bootstrap root", label)
		}
		position := compareReleasePosition(*identity, state.HighWater)
		if position > 0 {
			return fmt.Errorf("%s release exceeds the accepted high-water position", label)
		}
		if position == 0 && !state.sameAcceptedRelease(*identity, state.HighWater) {
			return fmt.Errorf("%s release equivocates at the accepted high-water position", label)
		}
	}
	if state.Active != nil && state.Previous != nil && state.Active.InstalledID == state.Previous.InstalledID {
		return errors.New("active and previous releases must be distinct")
	}
	if state.Pending != nil {
		if err := state.Pending.validateForStateSchema(state.Schema); err != nil {
			return err
		}
		if state.Pending.Candidate != state.HighWater {
			return errors.New("pending candidate must equal the accepted high-water release")
		}
		if state.Pending.TargetActive.BundleSecurityFloor < state.HighWater.MinimumSecurityFloor {
			return errors.New("pending target cannot process the persisted installer security floor")
		}
		if state.Pending.SourceActive == nil {
			if state.Pending.TargetActive.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
				return fmt.Errorf("first activation target writes agent-state schema %d, want current schema %d", state.Pending.TargetActive.AgentStateWriteVersion, agentstate.CurrentWriteVersion)
			}
		} else {
			source := *state.Pending.SourceActive
			target := state.Pending.TargetActive
			if !readsAgentStateSchema(target, source.AgentStateWriteVersion) {
				return fmt.Errorf("pending target cannot read source agent-state write schema %d", source.AgentStateWriteVersion)
			}
			if !readsAgentStateSchema(source, target.AgentStateWriteVersion) {
				return fmt.Errorf("pending source cannot read target agent-state write schema %d for rollback", target.AgentStateWriteVersion)
			}
		}
		if !sameOptionalReleaseExact(state.Pending.SourceActive, state.Active) {
			return errors.New("pending source_active must equal the recorded active release")
		}
		if !sameOptionalReleaseExact(state.Pending.SourcePrevious, state.Previous) {
			return errors.New("pending source_previous must equal the recorded previous release")
		}
		switch state.Pending.Operation {
		case OperationActivate:
			if state.Pending.TargetActive != state.Pending.Candidate {
				return errors.New("activate transaction target must equal its candidate")
			}
		case OperationRollback:
			if state.Previous == nil {
				return errors.New("rollback transaction requires a previous release")
			}
			if state.Pending.TargetActive != *state.Previous {
				return errors.New("rollback transaction target must equal the recorded previous release")
			}
		default:
			return fmt.Errorf("unsupported installer transaction operation %q", state.Pending.Operation)
		}
	}
	return nil
}

func (pending PendingTransaction) Validate() error {
	return pending.validateForStateSchema("")
}

func (pending PendingTransaction) validateForStateSchema(schema string) error {
	switch pending.Operation {
	case OperationActivate, OperationRollback:
	default:
		return fmt.Errorf("unsupported installer transaction operation %q", pending.Operation)
	}
	if err := pending.Candidate.validateForStateSchema(schema); err != nil {
		return fmt.Errorf("pending candidate: %w", err)
	}
	if err := pending.TargetActive.validateForStateSchema(schema); err != nil {
		return fmt.Errorf("pending target release: %w", err)
	}
	for label, source := range map[string]*ReleaseIdentity{
		"source active":   pending.SourceActive,
		"source previous": pending.SourcePrevious,
	} {
		if source == nil {
			continue
		}
		if err := source.validateForStateSchema(schema); err != nil {
			return fmt.Errorf("pending %s release: %w", label, err)
		}
		if compareReleasePosition(*source, pending.Candidate) > 0 {
			return fmt.Errorf("pending %s release exceeds candidate position", label)
		}
	}
	switch pending.Phase {
	case PhasePrepared, PhaseServicesStopped, PhaseCurrentSwitched, PhaseRollingBack:
	default:
		return fmt.Errorf("unsupported installer transaction phase %q", pending.Phase)
	}
	if _, err := parseCanonicalTime(pending.StartedAt); err != nil {
		return fmt.Errorf("pending started_at: %w", err)
	}
	if pending.NebulaWasActive && !pending.AgentWasActive {
		return errors.New("pending transaction cannot restore active Nebula without an active lifecycle agent")
	}
	if (pending.AgentWasActive || pending.NebulaWasActive) && !pending.RuntimeGateWasOpen {
		return errors.New("pending transaction cannot restore an active runtime with the fixed runtime gate closed")
	}
	return nil
}

// CheckCandidate enforces the durable high-water rule after threshold and
// artifact verification. A same-sequence operation is an exact retry only;
// higher sequences may advance the floor. Lower/equivocating candidates fail.
func (state State) CheckCandidate(candidate ReleaseIdentity) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if err := candidate.validateForStateSchema(state.Schema); err != nil {
		return err
	}
	if state.Schema == StateSchemaV3 && candidate.InstallerBootstrapRootSHA256 != state.HighWater.InstallerBootstrapRootSHA256 {
		return errors.New("candidate differs from the accepted installer bootstrap root")
	}
	if state.Pending != nil && !sameAuthenticatedRelease(candidate, state.Pending.Candidate) {
		return errors.New("an unfinished installer transaction must be completed before accepting another candidate")
	}
	position := compareReleasePosition(candidate, state.HighWater)
	if position < 0 {
		return fmt.Errorf("candidate release position (%d,%d) is below accepted position (%d,%d)", candidate.ReleaseEpoch, candidate.Sequence, state.HighWater.ReleaseEpoch, state.HighWater.Sequence)
	}
	if candidate.MinimumSecurityFloor < state.HighWater.MinimumSecurityFloor {
		return fmt.Errorf("candidate security floor %d is below accepted floor %d", candidate.MinimumSecurityFloor, state.HighWater.MinimumSecurityFloor)
	}
	if position == 0 && !state.sameAcceptedRelease(candidate, state.HighWater) {
		return errors.New("same-position candidate differs from the accepted authenticated release")
	}
	if state.Schema == StateSchemaV3 && position > 0 && candidate.TrustedRootVersion < state.HighWater.TrustedRootVersion {
		return fmt.Errorf("candidate trusted root version %d is below accepted root version %d", candidate.TrustedRootVersion, state.HighWater.TrustedRootVersion)
	}
	return nil
}

func compareReleasePosition(left, right ReleaseIdentity) int {
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

func (state State) sameAcceptedRelease(left, right ReleaseIdentity) bool {
	if state.Schema == StateSchemaV3 {
		return left == right
	}
	return sameAuthenticatedRelease(left, right)
}

func sameAuthenticatedRelease(left, right ReleaseIdentity) bool {
	return left.ReleaseEpoch == right.ReleaseEpoch &&
		left.TrustedRootVersion == right.TrustedRootVersion &&
		left.TrustedRootSHA256 == right.TrustedRootSHA256 &&
		left.InstallerBootstrapRootSHA256 == right.InstallerBootstrapRootSHA256 &&
		left.Sequence == right.Sequence &&
		left.ChannelManifestSHA256 == right.ChannelManifestSHA256 &&
		left.ReleaseManifestSHA256 == right.ReleaseManifestSHA256 &&
		left.ArtifactSHA256 == right.ArtifactSHA256 &&
		left.BundleManifestSHA256 == right.BundleManifestSHA256 &&
		left.Version == right.Version &&
		left.MinimumSecurityFloor == right.MinimumSecurityFloor &&
		left.BundleSecurityFloor == right.BundleSecurityFloor &&
		left.AgentStateReadMin == right.AgentStateReadMin &&
		left.AgentStateReadMax == right.AgentStateReadMax &&
		left.AgentStateWriteVersion == right.AgentStateWriteVersion &&
		left.InstalledID == right.InstalledID
}

// MigrateStateV2 maps a completely validated, quiescent legacy state to the
// immutable root carried by the compiled bootstrap. rootHistoryEmpty must come
// from the root store while its process lock is held; migration never guesses
// the trust version after any persisted root transition exists.
func MigrateStateV2(legacy State, bootstrap installtrust.Bootstrap, rootHistoryEmpty bool) (State, error) {
	if legacy.Schema != LegacyStateSchema {
		return State{}, fmt.Errorf("state migration requires schema %q", LegacyStateSchema)
	}
	if err := legacy.Validate(); err != nil {
		return State{}, fmt.Errorf("legacy installer state: %w", err)
	}
	if legacy.Pending != nil {
		return State{}, errors.New("legacy installer state has an unfinished transaction")
	}
	if !rootHistoryEmpty {
		return State{}, errors.New("legacy installer state cannot migrate after root history exists")
	}
	_, trusted, err := installtrust.EncodeBootstrap(installtrust.BootstrapSpec{InitialRoot: bootstrap.InitialRootRaw})
	if err != nil {
		return State{}, fmt.Errorf("installer bootstrap: %w", err)
	}
	providedRootRaw, err := releasetrust.EncodeRoot(bootstrap.InitialRoot.Document)
	if err != nil || !bytes.Equal(providedRootRaw, bootstrap.InitialRootRaw) || bootstrap.InitialRoot.SHA256 != trusted.InitialRoot.SHA256 {
		return State{}, errors.New("installer bootstrap parsed root does not match its canonical initial-root bytes")
	}
	if trusted.SHA256 != bootstrap.SHA256 || trusted.InitialRootSHA256 != bootstrap.InitialRootSHA256 ||
		trusted.LegacyPolicySHA256 != bootstrap.LegacyPolicySHA256 {
		return State{}, errors.New("installer bootstrap identity does not match its canonical initial root")
	}
	root := trusted.InitialRoot.Document
	if root.Version != 1 || root.ReleaseEpoch != 1 {
		return State{}, errors.New("state migration requires initial root version 1 and release epoch 1")
	}
	if legacy.TrustPolicySHA256 != trusted.LegacyPolicySHA256 {
		return State{}, errors.New("legacy installer trust policy does not match the bootstrap release delegation")
	}
	if legacy.Channel != root.Channel {
		return State{}, errors.New("legacy installer channel does not match the bootstrap root")
	}

	migrated := deepCopyState(legacy)
	migrated.Schema = StateSchemaV3
	migrated.TrustPolicySHA256 = ""
	migrated.BootstrapTrustSHA256 = trusted.SHA256
	migrate := func(identity *ReleaseIdentity) {
		if identity == nil {
			return
		}
		identity.ReleaseEpoch = 1
		identity.TrustedRootVersion = 1
		identity.TrustedRootSHA256 = trusted.InitialRootSHA256
		identity.InstallerBootstrapRootSHA256 = trusted.InitialRootSHA256
	}
	migrate(&migrated.HighWater)
	migrate(migrated.Active)
	migrate(migrated.Previous)
	if err := migrated.Validate(); err != nil {
		return State{}, fmt.Errorf("migrated installer state: %w", err)
	}
	return migrated, nil
}

func readsAgentStateSchema(identity ReleaseIdentity, version uint64) bool {
	return version >= identity.AgentStateReadMin && version <= identity.AgentStateReadMax
}

func sameOptionalRelease(left, right *ReleaseIdentity) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return sameAuthenticatedRelease(*left, *right)
}

func sameOptionalReleaseExact(left, right *ReleaseIdentity) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func parseCanonicalTime(value string) (time.Time, error) {
	if strings.TrimSpace(value) != value {
		return time.Time{}, errors.New("must not contain surrounding whitespace")
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("must be canonical UTC RFC3339 without fractional seconds")
	}
	return parsed.UTC(), nil
}

func validateSemVer(version string) error {
	if version == "" || len(version) > 128 || strings.Count(version, "+") > 1 {
		return errors.New("invalid SemVer length or build metadata")
	}
	mainAndBuild := strings.SplitN(version, "+", 2)
	if len(mainAndBuild) == 2 && !validSemVerIdentifiers(mainAndBuild[1], false) {
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
	if len(mainAndPre) == 2 && !validSemVerIdentifiers(mainAndPre[1], true) {
		return errors.New("invalid SemVer prerelease")
	}
	return nil
}

func validSemVerIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	parts := strings.Split(value, ".")
	for _, part := range parts {
		if part == "" || !identifierPattern.MatchString(part) {
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
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
}
